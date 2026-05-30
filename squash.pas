program squash;

{$apptype console}
{$mode delphi}

// Author: www.xelitan.com
// License: MIT

uses
  SysUtils, Classes, squash_stream;

procedure Usage;
begin
  Writeln('Usage:');
  Writeln('  squash c inputfile outputfile    compress to SQSH Squash file');
  Writeln('  squash d inputfile outputfile    decompress SQSH Squash file');
  Writeln('  squash cr inputfile outputfile   raw 13-bit Squash LZW compress');
  Writeln('  squash dr inputfile outputfile   raw 13-bit Squash LZW decompress');
end;

var
  Mode: string;
  InFile, OutFile: TFileStream;
begin

  try
    if ParamCount <> 3 then
    begin
      Usage;
      Halt(1);
    end;

    Mode := LowerCase(ParamStr(1));
    InFile := TFileStream.Create(ParamStr(2), fmOpenRead or fmShareDenyWrite);
    try
      OutFile := TFileStream.Create(ParamStr(3), fmCreate);
      try
        if Mode = 'c' then
          SquashStream(InFile, OutFile)
        else if Mode = 'd' then
          UnsquashStream(InFile, OutFile)
        else if Mode = 'cr' then
          SquashRawStream(InFile, OutFile)
        else if Mode = 'dr' then
          UnsquashRawStream(InFile, OutFile)
        else
        begin
          Usage;
          Halt(1);
        end;
      finally
        OutFile.Free;
      end;
    finally
      InFile.Free;
    end;
  except
    on E: Exception do
    begin
      Writeln(StdErr, E.ClassName, ': ', E.Message);
      Halt(2);
    end;
  end;
end.
