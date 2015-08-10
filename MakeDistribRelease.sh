#!/bin/sh

v=1.0
foler=SerpentCipher

rm -f *.zip
mkdir -p $foler
cp ../KeePass-SerpentCipher/*.cs ../KeePass-SerpentCipher/*.csproj $foler
cp -r ../KeePass-SerpentCipher/Properties ../KeePass-SerpentCipher/Crypto $foler

mono KeePass.exe --plgx-create $foler
rm SerpentCipher.dll
rm -rf %foler%

zip SerpentCipher-$v.zip SerpentCipher.plgx License.txt Readme.txt

rm -rf ../KeePass-SerpentCipher/obj

cd ..
zip -r Build/SerpentCipher-$v-Source.zip KeePass-SerpentCipher -x '*/.git*'
