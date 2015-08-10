/*
 * DotNetCrypt - an open source library of cryptographic algorithms for .NET
 * Copyright (C) 2009 David Musgrove
 * 
 * This file is part of DotNetCrypt.
 *
 * DotNetCrypt is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * DotNetCrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Reflection;
using System.Security.Cryptography;

namespace DotNetCrypt
{
    static internal class Utils
    {
        static private RNGCryptoServiceProvider _generator;
        static private readonly object _generatorSyncObject = new object();

        static internal RNGCryptoServiceProvider RandomNumberGeneratorSingleton
        {
            get
            {
                if (_generator == null)
                {
                    lock (_generatorSyncObject)
                    {
                        if (_generator == null)
                        {
                            _generator = new RNGCryptoServiceProvider();
                        }
                    }
                }
                return _generator;
            }
        }

        static internal byte[] GenerateRandom(int length)
        {
            var result = new byte[length];
            RandomNumberGeneratorSingleton.GetBytes(result);
            return result;
        }

        static internal bool IsStreamMode(ExtendedCipherMode mode)
        {
            return mode == ExtendedCipherMode.CFB || mode == ExtendedCipherMode.OFB || mode == ExtendedCipherMode.CTR;
        }

        static internal void Write16BitWordsIntoBytesBigEndian(ushort[] words, byte[] bytes)
        {
            int byteCount = bytes.Length;
            for (int byteIndex = 0, wordIndex = 0; byteIndex < byteCount; )
            {
                bytes[byteIndex++] = (byte)(words[wordIndex] >> 8 & 0xff);
                bytes[byteIndex++] = (byte)(words[wordIndex++] & 0xff);
            }
        }

        static internal void Write16BitWordsIntoBytesLittleEndian(ushort[] words, byte[] bytes)
        {
            int byteCount = bytes.Length;
            for (int byteIndex = 0, wordIndex = 0; byteIndex < byteCount; )
            {
                bytes[byteIndex++] = (byte)(words[wordIndex] & 0xff);
                bytes[byteIndex++] = (byte)(words[wordIndex++] >> 8 & 0xff);
            }
        }

        static internal void WriteWordsIntoBytesBigEndian(uint[] words, byte[] bytes)
        {
            int byteCount = bytes.Length;
            for (int byteIndex = 0, wordIndex = 0; byteIndex < byteCount; )
            {
                bytes[byteIndex++] = (byte)(words[wordIndex] >> 24 & 0xff);
                bytes[byteIndex++] = (byte)(words[wordIndex] >> 16 & 0xff);
                bytes[byteIndex++] = (byte)(words[wordIndex] >> 8 & 0xff);
                bytes[byteIndex++] = (byte)(words[wordIndex++] & 0xff);
            }
        }

        static internal void Write64BitWordsIntoBytesBigEndian(ulong[] words, byte[] bytes)
        {
            int byteCount = bytes.Length;
            for (int byteIndex = 0, wordIndex = 0; byteIndex < byteCount; )
            {
                bytes[byteIndex++] = (byte)(words[wordIndex] >> 56 & 0xff);
                bytes[byteIndex++] = (byte)(words[wordIndex] >> 48 & 0xff);
                bytes[byteIndex++] = (byte)(words[wordIndex] >> 40 & 0xff);
                bytes[byteIndex++] = (byte)(words[wordIndex] >> 32 & 0xff);
                bytes[byteIndex++] = (byte)(words[wordIndex] >> 24 & 0xff);
                bytes[byteIndex++] = (byte)(words[wordIndex] >> 16 & 0xff);
                bytes[byteIndex++] = (byte)(words[wordIndex] >> 8 & 0xff);
                bytes[byteIndex++] = (byte)(words[wordIndex++] & 0xff);
            }
        }

        static internal ushort[] BytesTo16BitWordsBigEndian(byte[] bytes)
        {
            int count = bytes.Length;
            var words = new ushort[count >> 1];
            for (int byteIndex = 0, wordIndex = 0; byteIndex < count; )
            {
                words[wordIndex++] = (ushort)((bytes[byteIndex++] << 8) | bytes[byteIndex++]);
            }
            return words;
        }

        static internal ushort[] BytesTo16BitWordsLittleEndian(byte[] bytes)
        {
            int count = bytes.Length;
            var words = new ushort[count >> 1];
            for (int byteIndex = 0, wordIndex = 0; byteIndex < count; )
            {
                words[wordIndex++] = (ushort)(bytes[byteIndex++] | (bytes[byteIndex++] << 8));
            }
            return words;
        }

        static internal uint[] BytesToWordsBigEndian(byte[] bytes)
        {
            int count = bytes.Length;
            var words = new uint[count >> 2];
            for (int byteIndex = 0, wordIndex = 0; byteIndex < count; )
            {
                words[wordIndex++] = ((uint)bytes[byteIndex++] << 24) | ((uint)bytes[byteIndex++] << 16) |
                                     ((uint)bytes[byteIndex++] << 8) | bytes[byteIndex++];
            }
            return words;
        }

        static internal uint[] BytesToWordsBigEndian(byte[] bytes, int start, int count)
        {
            var words = new uint[count >> 2];
            for (int byteIndex = start, wordIndex = 0; byteIndex < start + count; )
            {
                words[wordIndex++] = ((uint)bytes[byteIndex++] << 24) | ((uint)bytes[byteIndex++] << 16) |
                                     ((uint)bytes[byteIndex++] << 8) | bytes[byteIndex++];
            }
            return words;
        }

        static internal ulong[] BytesTo64BitWordsBigEndian(byte[] bytes)
        {
            return BytesTo64BitWordsBigEndian(bytes, 0, bytes.Length);
        }

        static internal ulong[] BytesTo64BitWordsBigEndian(byte[] bytes, int start, int count)
        {
            var words = new ulong[count >> 3];
            for (int byteIndex = start, wordIndex = 0; byteIndex < start + count; )
            {
                words[wordIndex++] = ((ulong)bytes[byteIndex++] << 56) | ((ulong)bytes[byteIndex++] << 48) |
                                     ((ulong)bytes[byteIndex++] << 40) | ((ulong)bytes[byteIndex++] << 32) |
                                     ((ulong)bytes[byteIndex++] << 24) | ((ulong)bytes[byteIndex++] << 16) |
                                     ((ulong)bytes[byteIndex++] << 8) | bytes[byteIndex++];
            }
            return words;
        }

        static internal void WriteWordsIntoBytesLittleEndian(uint[] words, byte[] bytes)
        {
            int byteCount = bytes.Length;
            for (int byteIndex = 0, wordIndex = 0; byteIndex < byteCount; )
            {
                bytes[byteIndex++] = (byte)(words[wordIndex] & 0xff);
                bytes[byteIndex++] = (byte)(words[wordIndex] >> 8 & 0xff);
                bytes[byteIndex++] = (byte)(words[wordIndex] >> 16 & 0xff);
                bytes[byteIndex++] = (byte)(words[wordIndex++] >> 24 & 0xff);
            }
        }

        static internal void Write64BitWordsIntoBytesLittleEndian(ulong[] words, byte[] bytes)
        {
            int byteCount = bytes.Length;
            for (int byteIndex = 0, wordIndex = 0; byteIndex < byteCount; )
            {
                bytes[byteIndex++] = (byte)(words[wordIndex] & 0xff);
                bytes[byteIndex++] = (byte)(words[wordIndex] >> 8 & 0xff);
                bytes[byteIndex++] = (byte)(words[wordIndex] >> 16 & 0xff);
                bytes[byteIndex++] = (byte)(words[wordIndex] >> 24 & 0xff);
                bytes[byteIndex++] = (byte)(words[wordIndex] >> 32 & 0xff);
                bytes[byteIndex++] = (byte)(words[wordIndex] >> 40 & 0xff);
                bytes[byteIndex++] = (byte)(words[wordIndex] >> 48 & 0xff);
                bytes[byteIndex++] = (byte)(words[wordIndex++] >> 56 & 0xff);
            }
        }

        static internal uint[] BytesToWordsLittleEndian(byte[] bytes)
        {
            return BytesToWordsLittleEndian(bytes, 0, bytes.Length);
        }

        static internal uint[] BytesToWordsLittleEndian(byte[] bytes, int start, int count)
        {
            var words = new uint[count >> 2];
            for (int byteIndex = start, wordIndex = 0; byteIndex < start + count; )
            {
                words[wordIndex++] = bytes[byteIndex++] | ((uint)bytes[byteIndex++] << 8) |
                                     ((uint)bytes[byteIndex++] << 16) | ((uint)bytes[byteIndex++] << 24);
            }
            return words;
        }

        static internal ulong[] BytesTo64BitWordsLittleEndian(byte[] bytes)
        {
            return BytesTo64BitWordsLittleEndian(bytes, 0, bytes.Length);
        }

        static internal ulong[] BytesTo64BitWordsLittleEndian(byte[] bytes, int start, int count)
        {
            var words = new ulong[count >> 3];
            for (int byteIndex = start, wordIndex = 0; byteIndex < start + count; )
            {
                words[wordIndex++] = bytes[byteIndex++] | ((ulong)bytes[byteIndex++] << 8) |
                                     ((ulong)bytes[byteIndex++] << 16) | ((ulong)bytes[byteIndex++] << 24) |
                                     ((ulong)bytes[byteIndex++] << 32) | ((ulong)bytes[byteIndex++] << 40) |
                                     ((ulong)bytes[byteIndex++] << 48) | ((ulong)bytes[byteIndex++] << 56);
            }
            return words;
        }

        static internal ICryptoTransform NewEncryptor(ISymmetricAlgorithm algorithm, Type type, byte[] rgbKey, ExtendedCipherMode mode, byte[] rgbIv, TransformDirection encryptDirection)
        {
            if (rgbKey == null)
            {
                rgbKey = algorithm.GenerateNonWeakKey();
            }
            if ((mode != ExtendedCipherMode.ECB) && (rgbIv == null))
            {
                rgbIv = new byte[algorithm.BlockSize / 8];
                RandomNumberGeneratorSingleton.GetBytes(rgbIv);
            }
            ConstructorInfo constructor = type.GetConstructor(BindingFlags.Instance | BindingFlags.NonPublic, null,
                                                              new[] { typeof(ISymmetricAlgorithm), typeof(byte[]), typeof(byte[]),
                                                                      typeof(TransformDirection)}, null);
            return (ICryptoTransform)constructor.Invoke(new object[] {algorithm, rgbKey, rgbIv, encryptDirection});
            //return (ICryptoTransform)Activator.CreateInstance(type, BindingFlags.NonPublic, null, new object[] { algorithm, rgbKey, rgbIv, encryptDirection }, null);
        }
    }
}
