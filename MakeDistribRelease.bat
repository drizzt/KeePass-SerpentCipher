SET z=D:\Apps\Core\7-Zip\7z.exe
SET v=1.0
SET foler=SerpentCipher

mkdir %foler%
xcopy ..\KeePass-SerpentCipher\*.cs %foler% /Y
xcopy ..\KeePass-SerpentCipher\SerpentCipher.csproj %foler%\ /Y
xcopy ..\KeePass-SerpentCipher\Properties %foler%\Properties /I /E /Y
xcopy ..\KeePass-SerpentCipher\Crypto %foler%\Crypto /I /E /Y

KeePass.exe --plgx-create %foler%
del SerpentCipher.dll
rd /s /q %foler%

%z% a SerpentCipher-%v%.zip SerpentCipher.plgx
%z% a SerpentCipher-%v%.zip License.txt
%z% a SerpentCipher-%v%.zip Readme.txt

rd /s /q ..\KeePass-SerpentCipher\obj
%z% a SerpentCipher-%v%-Source.zip ..\KeePass-SerpentCipher
%z% d SerpentCipher-%v%-Source.zip .git -r

