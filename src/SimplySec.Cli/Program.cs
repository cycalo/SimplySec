using System.Text;
using SimplySec.Commands;

Console.OutputEncoding = new UTF8Encoding(false);
return new Cli(new CliHost()).Run(args);
