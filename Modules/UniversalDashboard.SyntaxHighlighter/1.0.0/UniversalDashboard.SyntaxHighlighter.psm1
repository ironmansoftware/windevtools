
$IndexJs = Get-ChildItem "$PSScriptRoot\index.*.bundle.js"
$JsFiles = Get-ChildItem "$PSScriptRoot\*.bundle.js"
$Maps = Get-ChildItem "$PSScriptRoot\*.map"

$AssetId = [UniversalDashboard.Services.AssetService]::Instance.RegisterScript($IndexJs.FullName)

foreach($item in $JsFiles)
{
    [UniversalDashboard.Services.AssetService]::Instance.RegisterScript($item.FullName) | Out-Null
}

foreach($item in $Maps)
{
    [UniversalDashboard.Services.AssetService]::Instance.RegisterScript($item.FullName) | Out-Null
}

function New-UDSyntaxHighlighter {
    param(
        [Parameter()]
        [string]$Id = (New-Guid).ToString(),
        [Parameter(Mandatory = $true)]
        [string]$Code,
        [Parameter(Mandatory = $true)]
        [ValidateSet('oneC','abnf','accesslog','actionscript','ada','angelscript','apache','applescript','arcade','arduino','armasm','asciidoc','aspectj','autohotkey','autoit','avrasm','awk','axapta','bash','basic','bnf','brainfuck','cal','capnproto','ceylon','clean','clojureRepl','clojure','cmake','coffeescript','coq','cos','cpp','crmsh','crystal','cs','csp','css','d','dart','delphi','diff','django','dns','dockerfile','dos','dsconfig','dts','dust','ebnf','elixir','elm','erb','erlangRepl','erlang','excel','fix','flix','fortran','fsharp','gams','gauss','gcode','gherkin','glsl','gml','go','golo','gradle','groovy','haml','handlebars','haskell','haxe','hsp','htmlbars','http','hy','inform7','ini','irpf90','isbl','java','javascript','jbossCli','json','juliaRepl','julia','kotlin','lasso','ldif','leaf','less','lisp','livecodeserver','livescript','llvm','lsl','lua','makefile','markdown','mathematica','matlab','maxima','mel','mercury','mipsasm','mizar','mojolicious','monkey','moonscript','n1ql','nginx','nimrod','nix','nsis','objectivec','ocaml','openscad','oxygene','parser3','perl','pf','pgsql','php','plaintext','pony','powershell','processing','profile','prolog','properties','protobuf','puppet','purebasic','python','q','qml','r','reasonml','rib','roboconf','routeros','rsl','ruby','ruleslanguage','rust','sas','scala','scheme','scilab','scss','shell','smali','smalltalk','sml','sqf','sql','stan','stata','step21','stylus','subunit','swift','taggerscript','tap','tcl','tex','thrift','tp','twig','typescript','vala','vbnet','vbscriptHtml','vbscript','verilog','vhdl','vim','x86asm','xl','xml','xquery','yaml','zephir')]
        [string]$Language,
        [Parameter()]
        [ValidateSet('vs', 'dark', 'github')]
        [string]$Style = 'vs'
    )

    End {
        @{
            assetId = $AssetId 
            isPlugin = $true 
            type = "ud-syntaxhighlighter"

            id = $Id
            code = $Code 
            language = $Language
            style = $Style
        }
    }
}