unit squash_stream2;

{$mode delphi}

// Based on RISC OS de-archiver, MIT license
// Author: www.xelitan.com
// License: MIT

interface

uses
  Classes, SysUtils;

type
  ESquashError = class(Exception);

procedure SquashStream(InFile, OutFile: TFileStream; LoadAddr: LongWord = 0; ExecAddr: LongWord = 0; MaxBits: Integer = 12);
procedure UnsquashStream(InFile, OutFile: TFileStream);

{ Raw Squash LZW without the outer SQSH file header and without Unix-compress
  magic bytes. This is the form used as an archive compression method. }
procedure SquashRawStream(InStream, OutStream: TStream; MaxBits: Integer = 13);
procedure UnsquashRawStream(InStream, OutStream: TStream; ExpectedSize: Int64 = -1; MaxBits: Integer = 13);

{ Unix compress payload helpers. RISC OS standalone SQSH/,fca files normally
  store this form after the 20-byte SQSH metadata header: 1F 9D flags + LZW. }
procedure CompressLZWStream(InStream, OutStream: TStream; MaxBits: Integer = 12; BlockMode: Boolean = True);
procedure UncompressLZWStream(InStream, OutStream: TStream; ExpectedSize: Int64 = -1);

implementation

const
  SQ_MAGIC     = 'SQSH';
  MIN_BITS     = 9;
  MAX_BITS     = 13;
  CLEAR_CODE   = 256;
  FIRST_CODE   = 257;
  MAX_CODES    = 1 shl MAX_BITS; // 8192
  HASH_SIZE    = 32749;
  MAGIC_1      = $1f;
  MAGIC_2      = $9d;
  BLOCK_FLAG   = $80;

type
  TPrefixTable = array[0..MAX_CODES - 1] of Integer;
  TCharTable   = array[0..MAX_CODES - 1] of Byte;

  THashEntry = record
    Used: Boolean;
    Prefix: Integer;
    Ch: Byte;
    Code: Integer;
  end;

  THashTable = array[0..HASH_SIZE - 1] of THashEntry;

  TCodeWriter = class
  private
    FOut: TStream;
    FBits: Integer;
    FMask: LongWord;
    FBuffer: UInt64;
    FBitsUsed: Integer;
    FGroup: array[0..MAX_BITS - 1] of Byte;
    FGroupLen: Integer;
    procedure AppendByte(B: Byte);
  public
    constructor Create(AOut: TStream);
    procedure SetCodeBits(ABits: Integer);
    procedure WriteCode(Code: Integer);
    procedure Flush;
  end;

  TCodeReader = class
  private
    FIn: TStream;
    FBits: Integer;
    FMask: LongWord;
    FBuffer: UInt64;
    FBitsAvail: Integer;
    FGroup: array[0..MAX_BITS - 1] of Byte;
    FGroupPos: Integer;
    FGroupLen: Integer;
    FEndOfInput: Boolean;
    function ReadByteFromGroup(out B: Byte): Boolean;
  public
    constructor Create(AIn: TStream);
    procedure SetCodeBits(ABits: Integer);
    function ReadCode(out Code: Integer): Boolean;
  end;

procedure CheckMaxBits(MaxBits: Integer);
begin
  if (MaxBits < MIN_BITS) or (MaxBits > MAX_BITS) then
    raise ESquashError.CreateFmt('Unsupported LZW bit size %d; expected %d..%d', [MaxBits, MIN_BITS, MAX_BITS]);
end;

procedure ReadExact(S: TStream;
var Buffer;
Count: LongInt);
begin
  if Count = 0 then
    Exit;
  if S.Read(Buffer, Count) <> Count then
    raise ESquashError.Create('Unexpected end of stream');
end;

procedure WriteByte(S: TStream;
B: Byte);
begin
  S.WriteBuffer(B, 1);
end;

function ReadByte(S: TStream): Byte;
begin
  ReadExact(S, Result, 1);
end;

function ReadLE32(S: TStream): LongWord;
var
  B: array[0..3] of Byte;
begin
  ReadExact(S, B, 4);
  Result := LongWord(B[0]) or (LongWord(B[1]) shl 8) or
            (LongWord(B[2]) shl 16) or (LongWord(B[3]) shl 24);
end;

procedure WriteLE32(S: TStream; V: LongWord);
var
  B: array[0..3] of Byte;
begin
  B[0] := Byte(V and $ff);
  B[1] := Byte((V shr 8) and $ff);
  B[2] := Byte((V shr 16) and $ff);
  B[3] := Byte((V shr 24) and $ff);
  S.WriteBuffer(B, 4);
end;

{ TCodeWriter }

constructor TCodeWriter.Create(AOut: TStream);
begin
  inherited Create;
  FOut := AOut;
  FBits := MIN_BITS;
  FMask := (LongWord(1) shl FBits) - 1;
  FBuffer := 0;
  FBitsUsed := 0;
  FGroupLen := 0;
end;

procedure TCodeWriter.AppendByte(B: Byte);
begin
  FGroup[FGroupLen] := B;
  Inc(FGroupLen);
  if FGroupLen = FBits then
  begin
    FOut.WriteBuffer(FGroup[0], FGroupLen);
    FGroupLen := 0;
  end;
end;

procedure TCodeWriter.SetCodeBits(ABits: Integer);
begin
  if ABits = FBits then
    Exit;
  Flush;
// ncompress aligns code-size changes at byte groups
  FBits := ABits;
  FMask := (LongWord(1) shl FBits) - 1;
end;

procedure TCodeWriter.WriteCode(Code: Integer);
var
  B: Byte;
begin
  FBuffer := FBuffer or ((UInt64(Code) and FMask) shl FBitsUsed);
  Inc(FBitsUsed, FBits);
  while FBitsUsed >= 8 do
  begin
    B := Byte(FBuffer and $ff);
    AppendByte(B);
    FBuffer := FBuffer shr 8;
    Dec(FBitsUsed, 8);
  end;
end;

procedure TCodeWriter.Flush;
var
  B: Byte;
begin
  while FBitsUsed > 0 do
  begin
    B := Byte(FBuffer and $ff);
    AppendByte(B);
    FBuffer := FBuffer shr 8;
    if FBitsUsed > 8 then
      Dec(FBitsUsed, 8)
    else
      FBitsUsed := 0;
  end;
  if FGroupLen > 0 then
  begin
    FOut.WriteBuffer(FGroup[0], FGroupLen);
    FGroupLen := 0;
  end;
end;

{ TCodeReader }

constructor TCodeReader.Create(AIn: TStream);
begin
  inherited Create;
  FIn := AIn;
  FBits := MIN_BITS;
  FMask := (LongWord(1) shl FBits) - 1;
  FBuffer := 0;
  FBitsAvail := 0;
  FGroupPos := 0;
  FGroupLen := 0;
  FEndOfInput := False;
end;

procedure TCodeReader.SetCodeBits(ABits: Integer);
begin
  if ABits = FBits then
    Exit;
  FBits := ABits;
  FMask := (LongWord(1) shl FBits) - 1;
  FBuffer := 0;
  FBitsAvail := 0;
  FGroupPos := FGroupLen;
// discard any partial old-width group bytes
end;

function TCodeReader.ReadByteFromGroup(out B: Byte): Boolean;
var
  N: LongInt;
begin
  Result := False;
  if FGroupPos >= FGroupLen then
  begin
    if FEndOfInput then
      Exit;
    N := FIn.Read(FGroup[0], FBits);
    if N <= 0 then
    begin
      FEndOfInput := True;
      Exit;
    end;
    FGroupLen := N;
    FGroupPos := 0;
  end;
  B := FGroup[FGroupPos];
  Inc(FGroupPos);
  Result := True;
end;

function TCodeReader.ReadCode(out Code: Integer): Boolean;
var
  B: Byte;
begin
  while FBitsAvail < FBits do
  begin
    if not ReadByteFromGroup(B) then
      Exit(False);
    FBuffer := FBuffer or (UInt64(B) shl FBitsAvail);
    Inc(FBitsAvail, 8);
  end;
  Code := Integer(FBuffer and FMask);
  FBuffer := FBuffer shr FBits;
  Dec(FBitsAvail, FBits);
  Result := True;
end;

function HashOf(Prefix: Integer; Ch: Byte): Integer;
begin
  Result := ((Prefix shl 8) xor Ch) mod HASH_SIZE;
  if Result < 0 then
    Inc(Result, HASH_SIZE);
end;

procedure HashClear(var H: THashTable);
var
  I: Integer;
begin
  for I := Low(H) to High(H) do
    H[I].Used := False;
end;

function HashFind(var H: THashTable; Prefix: Integer; Ch: Byte; out Code: Integer): Boolean;
var
  I, Start: Integer;
begin
  Start := HashOf(Prefix, Ch);
  I := Start;
  repeat
    if not H[I].Used then
      Exit(False);
    if (H[I].Prefix = Prefix) and (H[I].Ch = Ch) then
    begin
      Code := H[I].Code;
      Exit(True);
    end;
    Inc(I);
    if I = HASH_SIZE then
      I := 0;
  until I = Start;
  Result := False;
end;

procedure HashAdd(var H: THashTable; Prefix: Integer; Ch: Byte; Code: Integer);
var
  I: Integer;
begin
  I := HashOf(Prefix, Ch);
  while H[I].Used do
  begin
    Inc(I);
    if I = HASH_SIZE then
      I := 0;
  end;
  H[I].Used := True;
  H[I].Prefix := Prefix;
  H[I].Ch := Ch;
  H[I].Code := Code;
end;

procedure SquashRawStream(InStream, OutStream: TStream; MaxBits: Integer);
var
  Dict: THashTable;
  Writer: TCodeWriter;
  Prefix, FoundCode, NextCode: Integer;
  DecoderNextCode, MaxCode, Bits, CodesWritten, MaxCodeCount: Integer;
  R: LongInt;
  Ch: Byte;

  procedure EmitCode(Code: Integer);
  begin
    Writer.WriteCode(Code);
    Inc(CodesWritten);
    if CodesWritten > 1 then
    begin
      if DecoderNextCode < MaxCodeCount then
        Inc(DecoderNextCode);
      if (DecoderNextCode > MaxCode) and (Bits < MaxBits) then
      begin
        Inc(Bits);
        MaxCode := (1 shl Bits) - 1;
        Writer.SetCodeBits(Bits);
      end;
    end;
  end;

begin
  CheckMaxBits(MaxBits);
  MaxCodeCount := 1 shl MaxBits;
  HashClear(Dict);
  Writer := TCodeWriter.Create(OutStream);
  try
    Bits := MIN_BITS;
    MaxCode := (1 shl Bits) - 1;
    NextCode := FIRST_CODE;
    DecoderNextCode := FIRST_CODE;
    CodesWritten := 0;

    R := InStream.Read(Ch, 1);
    if R = 0 then
      Exit;
    Prefix := Ch;

    while InStream.Read(Ch, 1) = 1 do
    begin
      if HashFind(Dict, Prefix, Ch, FoundCode) then
        Prefix := FoundCode
      else
      begin
        EmitCode(Prefix);
        if NextCode < MaxCodeCount then
        begin
          HashAdd(Dict, Prefix, Ch, NextCode);
          Inc(NextCode);
        end;
        Prefix := Ch;
      end;
    end;
    EmitCode(Prefix);
    Writer.Flush;
  finally
    Writer.Free;
  end;
end;

procedure DecodeLZWPayload(InStream, OutStream: TStream; ExpectedSize: Int64; MaxBits: Integer; BlockMode: Boolean);
var
  Prefix: TPrefixTable;
  Suffix: TCharTable;
  Reader: TCodeReader;
  Stack: array[0..MAX_CODES - 1] of Byte;
  StackTop: Integer;
  Code, InCode, OldCode, FinChar, NextCode, MaxCode, Bits, MaxCodeCount, FirstFree: Integer;
  OutCount: Int64;

  procedure PutByte(B: Byte);
  begin
    if (ExpectedSize >= 0) and (OutCount >= ExpectedSize) then
      Exit;
    OutStream.WriteBuffer(B, 1);
    Inc(OutCount);
  end;

  procedure ResetDictionary(FirstCodeAfterReset: Boolean);
  var
    I: Integer;
  begin
    for I := 0 to 255 do
    begin
      Prefix[I] := I;
      Suffix[I] := Byte(I);
    end;
    Bits := MIN_BITS;
    MaxCode := (1 shl Bits) - 1;
    Reader.SetCodeBits(Bits);
    if BlockMode then
      FirstFree := FIRST_CODE
    else
      FirstFree := CLEAR_CODE;
    NextCode := FirstFree;
    if FirstCodeAfterReset then
      OldCode := -1;
  end;

begin
  CheckMaxBits(MaxBits);
  MaxCodeCount := 1 shl MaxBits;
  Reader := TCodeReader.Create(InStream);
  try
    OutCount := 0;
    OldCode := -1;
    FinChar := -1;
    ResetDictionary(True);

    while True do
    begin
      if (ExpectedSize >= 0) and (OutCount >= ExpectedSize) then
        Break;

      if (NextCode > MaxCode) and (Bits < MaxBits) then
      begin
        Inc(Bits);
        if Bits = MaxBits then
          MaxCode := MaxCodeCount
        else
          MaxCode := (1 shl Bits) - 1;
        Reader.SetCodeBits(Bits);
      end;

      if not Reader.ReadCode(Code) then
        Break;

      if OldCode = -1 then
      begin
        if Code > 255 then
          raise ESquashError.Create('Corrupt LZW data: first code is not a literal');
        FinChar := Code;
        OldCode := Code;
        PutByte(Byte(Code));
        Continue;
      end;

      if BlockMode and (Code = CLEAR_CODE) then
      begin
        ResetDictionary(True);
        Continue;
      end;

      InCode := Code;
      StackTop := High(Stack) + 1;
      if Code >= NextCode then
      begin
        if Code > NextCode then
          raise ESquashError.Create('Corrupt LZW data: bad KwKwK code');
        Dec(StackTop);
        Stack[StackTop] := Byte(FinChar);
        Code := OldCode;
      end;

      while Code >= 256 do
      begin
        if (Code < 0) or (Code >= MAX_CODES) then
          raise ESquashError.Create('Corrupt LZW data: code out of range');
        Dec(StackTop);
        if StackTop < 0 then
          raise ESquashError.Create('Corrupt LZW data: expansion stack overflow');
        Stack[StackTop] := Suffix[Code];
        Code := Prefix[Code];
      end;

      FinChar := Code;
      Dec(StackTop);
      Stack[StackTop] := Byte(FinChar);

      while StackTop <= High(Stack) do
      begin
        PutByte(Stack[StackTop]);
        Inc(StackTop);
        if (ExpectedSize >= 0) and (OutCount >= ExpectedSize) then
          Break;
      end;

      if NextCode < MaxCodeCount then
      begin
        Prefix[NextCode] := OldCode;
        Suffix[NextCode] := Byte(FinChar);
        Inc(NextCode);
      end;
      OldCode := InCode;
    end;
  finally
    Reader.Free;
  end;
end;


procedure CompressLZWStream(InStream, OutStream: TStream; MaxBits: Integer; BlockMode: Boolean);
var
  Flags: Byte;
begin
  CheckMaxBits(MaxBits);
  WriteByte(OutStream, MAGIC_1);
  WriteByte(OutStream, MAGIC_2);
  Flags := Byte(MaxBits);
  if BlockMode then
    Flags := Flags or BLOCK_FLAG;
  WriteByte(OutStream, Flags);
  SquashRawStream(InStream, OutStream, MaxBits);
end;

procedure UncompressLZWStream(InStream, OutStream: TStream; ExpectedSize: Int64);
var
  B1, B2, Flags: Byte;
  MaxBits: Integer;
  BlockMode: Boolean;
begin
  B1 := ReadByte(InStream);
  B2 := ReadByte(InStream);
  if (B1 <> MAGIC_1) or (B2 <> MAGIC_2) then
    raise ESquashError.Create('Bad Unix compress magic in SQSH payload');
  Flags := ReadByte(InStream);
  MaxBits := Flags and $1f;
  BlockMode := (Flags and BLOCK_FLAG) <> 0;
  CheckMaxBits(MaxBits);
  DecodeLZWPayload(InStream, OutStream, ExpectedSize, MaxBits, BlockMode);
end;

procedure SquashStream(InFile, OutFile: TFileStream;
LoadAddr: LongWord;
ExecAddr: LongWord;
MaxBits: Integer);
var
  Magic: array[0..3] of AnsiChar;
  SavePos, OrigLen: Int64;
begin
  CheckMaxBits(MaxBits);
  SavePos := InFile.Position;
  OrigLen := InFile.Size - SavePos;
  if OrigLen < 0 then
    OrigLen := 0;
  if OrigLen > High(LongWord) then
    raise ESquashError.Create('Input is too large for the Squash file header');

  Magic[0] := 'S';
  Magic[1] := 'Q';
  Magic[2] := 'S';
  Magic[3] := 'H';

  OutFile.WriteBuffer(Magic, 4);
  WriteLE32(OutFile, LongWord(OrigLen));
  WriteLE32(OutFile, LoadAddr);
  WriteLE32(OutFile, ExecAddr);
  WriteLE32(OutFile, 0);
  CompressLZWStream(InFile, OutFile, MaxBits, True);
end;

procedure UnsquashStream(InFile, OutFile: TFileStream);
var
  Magic: array[0..3] of AnsiChar;
  OrigLen: LongWord;
  P: Int64;
  B: array[0..1] of Byte;
begin
  ReadExact(InFile, Magic, 4);
  if (Magic[0] <> 'S') or (Magic[1] <> 'Q') or (Magic[2] <> 'S') or (Magic[3] <> 'H') then
    raise ESquashError.Create('Bad Squash magic; expected SQSH');
  OrigLen := ReadLE32(InFile);
  ReadLE32(InFile);
// load address
  ReadLE32(InFile);
// exec address
  ReadLE32(InFile);
// reserved/attributes

  { Actual standalone RISC OS Squash files place a Unix-compress stream here
    (1F 9D flags).  Older/raw callers may still have headerless data, so keep
    that as a fallback. }
  P := InFile.Position;
  if InFile.Read(B, 2) <> 2 then
    Exit;
  InFile.Position := P;
  if (B[0] = MAGIC_1) and (B[1] = MAGIC_2) then
    UncompressLZWStream(InFile, OutFile, OrigLen)
  else
    DecodeLZWPayload(InFile, OutFile, OrigLen, MAX_BITS, True);
end;

{ Replace the earlier declaration body. }
procedure UnsquashRawStream(InStream, OutStream: TStream; ExpectedSize: Int64; MaxBits: Integer);
begin
  DecodeLZWPayload(InStream, OutStream, ExpectedSize, MaxBits, True);
end;

end.
