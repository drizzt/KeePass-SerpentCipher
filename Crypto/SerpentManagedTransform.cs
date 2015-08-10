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

namespace DotNetCrypt
{
    /// <summary>
    /// Performs a cryptographic transformation of data using the
    /// <see cref="Serpent" /> algorithm. This class cannot be inherited.
    /// </summary>
    // ReSharper disable InconsistentNaming
    public sealed class SerpentManagedTransform : ManagedTransformBase
    // ReSharper restore InconsistentNaming
    {
        private byte[] _key;
        private uint[][] _expandedKey;

        private const uint PHI = 0x9e3779b9;

        #region S-box and LT arrays

        static private readonly uint[][] _sBox = {
                                    new uint[] {3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12},
                                    new uint[] {15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4},
                                    new uint[] {8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2},
                                    new uint[] {0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14},
                                    new uint[] {1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13},
                                    new uint[] {15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1},
                                    new uint[] {7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0},
                                    new uint[] {1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6},
                                    new uint[] {3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12},
                                    new uint[] {15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4},
                                    new uint[] {8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2},
                                    new uint[] {0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14},
                                    new uint[] {1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13},
                                    new uint[] {15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1},
                                    new uint[] {7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0},
                                    new uint[] {1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6},
                                    new uint[] {3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12},
                                    new uint[] {15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4},
                                    new uint[] {8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2},
                                    new uint[] {0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14},
                                    new uint[] {1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13},
                                    new uint[] {15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1},
                                    new uint[] {7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0},
                                    new uint[] {1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6},
                                    new uint[] {3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12},
                                    new uint[] {15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4},
                                    new uint[] {8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2},
                                    new uint[] {0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14},
                                    new uint[] {1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13},
                                    new uint[] {15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1},
                                    new uint[] {7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0},
                                    new uint[] {1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6}
                                };

        #endregion  

        internal SerpentManagedTransform(ISymmetricAlgorithm algorithm, byte[] rgbKey, byte[] rgbIv, TransformDirection transformDirection)
            : base(algorithm, rgbIv, transformDirection, Endianness.Little)
        {
            _key = rgbKey;
            ComputeKeySchedule();
        }

        private void ComputeKeySchedule()
        {
            _expandedKey = new uint[33][];
            var workingKey = new uint[132];
            uint[] fullKey = GetFullLengthKey();

            uint working = fullKey[0] ^ fullKey[3] ^ fullKey[5] ^ fullKey[7] ^ PHI ^ 0;
            workingKey[0] = working << 11 | working >> 21;
            working = fullKey[1] ^ fullKey[4] ^ fullKey[6] ^ workingKey[0] ^ PHI ^ 1;
            workingKey[1] = working << 11 | working >> 21;
            working = fullKey[2] ^ fullKey[5] ^ fullKey[7] ^ workingKey[1] ^ PHI ^ 2;
            workingKey[2] = working << 11 | working >> 21;
            working = fullKey[3] ^ fullKey[6] ^ workingKey[0] ^ workingKey[2] ^ PHI ^ 3;
            workingKey[3] = working << 11 | working >> 21;
            working = fullKey[4] ^ fullKey[7] ^ workingKey[1] ^ workingKey[3] ^ PHI ^ 4;
            workingKey[4] = working << 11 | working >> 21;
            working = fullKey[5] ^ workingKey[0] ^ workingKey[2] ^ workingKey[4] ^ PHI ^ 5;
            workingKey[5] = working << 11 | working >> 21;
            working = fullKey[6] ^ workingKey[1] ^ workingKey[3] ^ workingKey[5] ^ PHI ^ 6;
            workingKey[6] = working << 11 | working >> 21;
            working = fullKey[7] ^ workingKey[2] ^ workingKey[4] ^ workingKey[6] ^ PHI ^ 7;
            workingKey[7] = working << 11 | working >> 21;
            for (uint i = 8; i < 132; i++)
            {
                working = workingKey[i - 8] ^ workingKey[i - 5] ^ workingKey[i - 3] ^ workingKey[i - 1] ^ PHI ^ i;
                workingKey[i] = working << 11 | working >> 21;
            }
            for (int i = 0; i < 32 + 1; i++)
            {
                int box = (32 + 3 - i) & 0x1f;
                _expandedKey[i] = new uint[4];
                for (int j = 0; j < 32; j++)
                {
                    uint in1 = GetBit(workingKey, j, 4 * i) |
                               GetBit(workingKey, j, 4 * i + 1) << 1 |
                               GetBit(workingKey, j, 4 * i + 2) << 2 |
                               GetBit(workingKey, j, 4 * i + 3) << 3;
                    uint out1 = _sBox[box][in1];
                    _expandedKey[i][0] |= (out1 & 0x1) << j;
                    _expandedKey[i][1] |= (out1 >> 1 & 0x1) << (j);
                    _expandedKey[i][2] |= (out1 >> 2 & 0x1) << (j);
                    _expandedKey[i][3] |= (out1 >> 3 & 0x1) << (j);
                }
            }
        }

        private uint[] GetFullLengthKey()
        {
            var fullKey = new uint[8];
            Utils.BytesToWordsLittleEndian(_key, 0, 16).CopyTo(fullKey, 0);
            if (_key.Length > 0x10)
            {
                Utils.BytesToWordsLittleEndian(_key, 16, 8).CopyTo(fullKey, 4);
                if (_key.Length > 0x18)
                {
                    Utils.BytesToWordsLittleEndian(_key, 24, 8).CopyTo(fullKey, 6);
                }
                else
                {
                    fullKey[6] = 0x1;
                }
            }
            else
            {
                fullKey[4] = 0x1;
            }
            return fullKey;
        }

        static private uint GetBit(uint[] x, int p, int offset)
        {
            var rotation = p & 0x1f;
            return (x[offset + (p >> 5)] & ((uint)0x1 << rotation)) >> rotation;
        }

        /// <summary>
        /// Performs the encryption transformation on a block of bytes that
        /// have been translated into words using the big endian convention.
        /// </summary>
        /// <param name="plain">
        /// The words to encrypt.
        /// </param>
        [CLSCompliant(false)]
        protected internal override void Encrypt(uint[] plain)
        {
            uint plain0 = plain[0] ^ _expandedKey[0][0];
            uint plain1 = plain[1] ^ _expandedKey[0][1];
            uint plain2 = plain[2] ^ _expandedKey[0][2];
            uint plain3 = plain[3] ^ _expandedKey[0][3];

            uint temp01 = plain1 ^ plain2;
            uint temp02 = plain0 | plain3;
            uint temp03 = plain0 ^ plain1;
            uint alt3 = temp02 ^ temp01;
            uint temp05 = plain2 | alt3;
            uint temp06 = plain0 ^ plain3;
            uint temp07 = plain1 | plain2;
            uint temp08 = plain3 & temp05;
            uint temp09 = temp03 & temp07;
            uint alt2 = temp09 ^ temp08;
            uint temp11 = temp09 & alt2;
            uint temp12 = plain2 ^ plain3;
            uint temp13 = temp07 ^ temp11;
            uint temp14 = plain1 & temp06;
            uint temp15 = temp06 ^ temp13;
            uint alt0 = ~ temp15;
            uint temp17 = alt0 ^ temp14;
            uint alt1 = temp12 ^ temp17;

            plain0 = ((((alt0)) << (13)) | (((alt0)) >> (32 - (13))));
            plain2 = ((((alt2)) << (3)) | (((alt2)) >> (32 - (3))));
            plain1 = alt1 ^ plain0 ^ plain2;
            plain3 = alt3 ^ plain2 ^ (plain0 << 3);
            plain1 = ((((plain1)) << (1)) | (((plain1)) >> (32 - (1))));
            plain3 = ((((plain3)) << (7)) | (((plain3)) >> (32 - (7))));
            plain0 = plain0 ^ plain1 ^ plain3;
            plain2 = plain2 ^ plain3 ^ (plain1 << 7);
            plain0 = ((((plain0)) << (5)) | (((plain0)) >> (32 - (5))));
            plain2 = ((((plain2)) << (22)) | (((plain2)) >> (32 - (22))));
            plain0 ^= _expandedKey[1][0];
            plain1 ^= _expandedKey[1][1];
            plain2 ^= _expandedKey[1][2];
            plain3 ^= _expandedKey[1][3];

            temp01 = plain0 | plain3;
            temp02 = plain2 ^ plain3;
            temp03 = ~ plain1;
            uint temp04 = plain0 ^ plain2;
            temp05 = plain0 | temp03;
            temp06 = plain3 & temp04;
            temp07 = temp01 & temp02;
            temp08 = plain1 | temp06;
            alt2 = temp02 ^ temp05;
            uint temp10 = temp07 ^ temp08;
            temp11 = temp01 ^ temp10;
            temp12 = alt2 ^ temp11;
            temp13 = plain1 & plain3;
            alt3 = ~ temp10;
            alt1 = temp13 ^ temp12;
            uint temp16 = temp10 | alt1;
            temp17 = temp05 & temp16;
            alt0 = plain2 ^ temp17;

            plain0 = ((((alt0)) << (13)) | (((alt0)) >> (32 - (13))));
            plain2 = ((((alt2)) << (3)) | (((alt2)) >> (32 - (3))));
            plain1 = alt1 ^ plain0 ^ plain2;
            plain3 = alt3 ^ plain2 ^ (plain0 << 3);
            plain1 = ((((plain1)) << (1)) | (((plain1)) >> (32 - (1))));
            plain3 = ((((plain3)) << (7)) | (((plain3)) >> (32 - (7))));
            plain0 = plain0 ^ plain1 ^ plain3;
            plain2 = plain2 ^ plain3 ^ (plain1 << 7);
            plain0 = ((((plain0)) << (5)) | (((plain0)) >> (32 - (5))));
            plain2 = ((((plain2)) << (22)) | (((plain2)) >> (32 - (22))));
            plain0 ^= _expandedKey[2][0];
            plain1 ^= _expandedKey[2][1];
            plain2 ^= _expandedKey[2][2];
            plain3 ^= _expandedKey[2][3];

            temp01 = plain0 | plain2;
            temp02 = plain0 ^ plain1;
            temp03 = plain3 ^ temp01;
            alt0 = temp02 ^ temp03;
            temp05 = plain2 ^ alt0;
            temp06 = plain1 ^ temp05;
            temp07 = plain1 | temp05;
            temp08 = temp01 & temp06;
            temp09 = temp03 ^ temp07;
            temp10 = temp02 | temp09;
            alt1 = temp10 ^ temp08;
            temp12 = plain0 | plain3;
            temp13 = temp09 ^ alt1;
            temp14 = plain1 ^ temp13;
            alt3 = ~ temp09;
            alt2 = temp12 ^ temp14;

            plain0 = ((((alt0)) << (13)) | (((alt0)) >> (32 - (13))));
            plain2 = ((((alt2)) << (3)) | (((alt2)) >> (32 - (3))));
            plain1 = alt1 ^ plain0 ^ plain2;
            plain3 = alt3 ^ plain2 ^ (plain0 << 3);
            plain1 = ((((plain1)) << (1)) | (((plain1)) >> (32 - (1))));
            plain3 = ((((plain3)) << (7)) | (((plain3)) >> (32 - (7))));
            plain0 = plain0 ^ plain1 ^ plain3;
            plain2 = plain2 ^ plain3 ^ (plain1 << 7);
            plain0 = ((((plain0)) << (5)) | (((plain0)) >> (32 - (5))));
            plain2 = ((((plain2)) << (22)) | (((plain2)) >> (32 - (22))));
            plain0 ^= _expandedKey[3][0];
            plain1 ^= _expandedKey[3][1];
            plain2 ^= _expandedKey[3][2];
            plain3 ^= _expandedKey[3][3];

            temp01 = plain0 ^ plain2;
            temp02 = plain0 | plain3;
            temp03 = plain0 & plain3;
            temp04 = temp01 & temp02;
            temp05 = plain1 | temp03;
            temp06 = plain0 & plain1;
            temp07 = plain3 ^ temp04;
            temp08 = plain2 | temp06;
            temp09 = plain1 ^ temp07;
            temp10 = plain3 & temp05;
            temp11 = temp02 ^ temp10;
            alt3 = temp08 ^ temp09;
            temp13 = plain3 | alt3;
            temp14 = plain0 | temp07;
            temp15 = plain1 & temp13;
            alt2 = temp08 ^ temp11;
            alt0 = temp14 ^ temp15;
            alt1 = temp05 ^ temp04;

            plain0 = ((((alt0)) << (13)) | (((alt0)) >> (32 - (13))));
            plain2 = ((((alt2)) << (3)) | (((alt2)) >> (32 - (3))));
            plain1 = alt1 ^ plain0 ^ plain2;
            plain3 = alt3 ^ plain2 ^ (plain0 << 3);
            plain1 = ((((plain1)) << (1)) | (((plain1)) >> (32 - (1))));
            plain3 = ((((plain3)) << (7)) | (((plain3)) >> (32 - (7))));
            plain0 = plain0 ^ plain1 ^ plain3;
            plain2 = plain2 ^ plain3 ^ (plain1 << 7);
            plain0 = ((((plain0)) << (5)) | (((plain0)) >> (32 - (5))));
            plain2 = ((((plain2)) << (22)) | (((plain2)) >> (32 - (22))));
            plain0 ^= _expandedKey[4][0];
            plain1 ^= _expandedKey[4][1];
            plain2 ^= _expandedKey[4][2];
            plain3 ^= _expandedKey[4][3];

            temp01 = plain0 | plain1;
            temp02 = plain1 | plain2;
            temp03 = plain0 ^ temp02;
            temp04 = plain1 ^ plain3;
            temp05 = plain3 | temp03;
            temp06 = plain3 & temp01;
            alt3 = temp03 ^ temp06;
            temp08 = alt3 & temp04;
            temp09 = temp04 & temp05;
            temp10 = plain2 ^ temp06;
            temp11 = plain1 & plain2;
            temp12 = temp04 ^ temp08;
            temp13 = temp11 | temp03;
            temp14 = temp10 ^ temp09;
            temp15 = plain0 & temp05;
            temp16 = temp11 | temp12;
            alt2 = temp13 ^ temp08;
            alt1 = temp15 ^ temp16;
            alt0 = ~ temp14;

            plain0 = ((((alt0)) << (13)) | (((alt0)) >> (32 - (13))));
            plain2 = ((((alt2)) << (3)) | (((alt2)) >> (32 - (3))));
            plain1 = alt1 ^ plain0 ^ plain2;
            plain3 = alt3 ^ plain2 ^ (plain0 << 3);
            plain1 = ((((plain1)) << (1)) | (((plain1)) >> (32 - (1))));
            plain3 = ((((plain3)) << (7)) | (((plain3)) >> (32 - (7))));
            plain0 = plain0 ^ plain1 ^ plain3;
            plain2 = plain2 ^ plain3 ^ (plain1 << 7);
            plain0 = ((((plain0)) << (5)) | (((plain0)) >> (32 - (5))));
            plain2 = ((((plain2)) << (22)) | (((plain2)) >> (32 - (22))));
            plain0 ^= _expandedKey[5][0];
            plain1 ^= _expandedKey[5][1];
            plain2 ^= _expandedKey[5][2];
            plain3 ^= _expandedKey[5][3];

            temp01 = plain1 ^ plain3;
            temp02 = plain1 | plain3;
            temp03 = plain0 & temp01;
            temp04 = plain2 ^ temp02;
            temp05 = temp03 ^ temp04;
            alt0 = ~ temp05;
            temp07 = plain0 ^ temp01;
            temp08 = plain3 | alt0;
            temp09 = plain1 | temp05;
            temp10 = plain3 ^ temp08;
            temp11 = plain1 | temp07;
            temp12 = temp03 | alt0;
            temp13 = temp07 | temp10;
            temp14 = temp01 ^ temp11;
            alt2 = temp09 ^ temp13;
            alt1 = temp07 ^ temp08;
            alt3 = temp12 ^ temp14;

            plain0 = ((((alt0)) << (13)) | (((alt0)) >> (32 - (13))));
            plain2 = ((((alt2)) << (3)) | (((alt2)) >> (32 - (3))));
            plain1 = alt1 ^ plain0 ^ plain2;
            plain3 = alt3 ^ plain2 ^ (plain0 << 3);
            plain1 = ((((plain1)) << (1)) | (((plain1)) >> (32 - (1))));
            plain3 = ((((plain3)) << (7)) | (((plain3)) >> (32 - (7))));
            plain0 = plain0 ^ plain1 ^ plain3;
            plain2 = plain2 ^ plain3 ^ (plain1 << 7);
            plain0 = ((((plain0)) << (5)) | (((plain0)) >> (32 - (5))));
            plain2 = ((((plain2)) << (22)) | (((plain2)) >> (32 - (22))));
            plain0 ^= _expandedKey[6][0];
            plain1 ^= _expandedKey[6][1];
            plain2 ^= _expandedKey[6][2];
            plain3 ^= _expandedKey[6][3];

            temp01 = plain0 & plain3;
            temp02 = plain1 ^ plain2;
            temp03 = plain0 ^ plain3;
            temp04 = temp01 ^ temp02;
            temp05 = plain1 | plain2;
            alt1 = ~ temp04;
            temp07 = temp03 & temp05;
            temp08 = plain1 & alt1;
            temp09 = plain0 | plain2;
            temp10 = temp07 ^ temp08;
            temp11 = plain1 | plain3;
            temp12 = plain2 ^ temp11;
            temp13 = temp09 ^ temp10;
            alt2 = ~ temp13;
            temp15 = alt1 & temp03;
            alt3 = temp12 ^ temp07;
            temp17 = plain0 ^ plain1;
            uint temp18 = alt2 ^ temp15;
            alt0 = temp17 ^ temp18;

            plain0 = ((((alt0)) << (13)) | (((alt0)) >> (32 - (13))));
            plain2 = ((((alt2)) << (3)) | (((alt2)) >> (32 - (3))));
            plain1 = alt1 ^ plain0 ^ plain2;
            plain3 = alt3 ^ plain2 ^ (plain0 << 3);
            plain1 = ((((plain1)) << (1)) | (((plain1)) >> (32 - (1))));
            plain3 = ((((plain3)) << (7)) | (((plain3)) >> (32 - (7))));
            plain0 = plain0 ^ plain1 ^ plain3;
            plain2 = plain2 ^ plain3 ^ (plain1 << 7);
            plain0 = ((((plain0)) << (5)) | (((plain0)) >> (32 - (5))));
            plain2 = ((((plain2)) << (22)) | (((plain2)) >> (32 - (22))));
            plain0 ^= _expandedKey[7][0];
            plain1 ^= _expandedKey[7][1];
            plain2 ^= _expandedKey[7][2];
            plain3 ^= _expandedKey[7][3];

            temp01 = plain0 & plain2;
            temp02 = ~ plain3;
            temp03 = plain0 & temp02;
            temp04 = plain1 | temp01;
            temp05 = plain0 & plain1;
            temp06 = plain2 ^ temp04;
            alt3 = temp03 ^ temp06;
            temp08 = plain2 | alt3;
            temp09 = plain3 | temp05;
            temp10 = plain0 ^ temp08;
            temp11 = temp04 & alt3;
            alt1 = temp09 ^ temp10;
            temp13 = plain1 ^ alt1;
            temp14 = temp01 ^ alt1;
            temp15 = plain2 ^ temp05;
            temp16 = temp11 | temp13;
            temp17 = temp02 | temp14;
            alt0 = temp15 ^ temp17;
            alt2 = plain0 ^ temp16;

            plain0 = ((((alt0)) << (13)) | (((alt0)) >> (32 - (13))));
            plain2 = ((((alt2)) << (3)) | (((alt2)) >> (32 - (3))));
            plain1 = alt1 ^ plain0 ^ plain2;
            plain3 = alt3 ^ plain2 ^ (plain0 << 3);
            plain1 = ((((plain1)) << (1)) | (((plain1)) >> (32 - (1))));
            plain3 = ((((plain3)) << (7)) | (((plain3)) >> (32 - (7))));
            plain0 = plain0 ^ plain1 ^ plain3;
            plain2 = plain2 ^ plain3 ^ (plain1 << 7);
            plain0 = ((((plain0)) << (5)) | (((plain0)) >> (32 - (5))));
            plain2 = ((((plain2)) << (22)) | (((plain2)) >> (32 - (22))));
            plain0 ^= _expandedKey[8][0];
            plain1 ^= _expandedKey[8][1];
            plain2 ^= _expandedKey[8][2];
            plain3 ^= _expandedKey[8][3];

            temp01 = plain1 ^ plain2;
            temp02 = plain0 | plain3;
            temp03 = plain0 ^ plain1;
            alt3 = temp02 ^ temp01;
            temp05 = plain2 | alt3;
            temp06 = plain0 ^ plain3;
            temp07 = plain1 | plain2;
            temp08 = plain3 & temp05;
            temp09 = temp03 & temp07;
            alt2 = temp09 ^ temp08;
            temp11 = temp09 & alt2;
            temp12 = plain2 ^ plain3;
            temp13 = temp07 ^ temp11;
            temp14 = plain1 & temp06;
            temp15 = temp06 ^ temp13;
            alt0 = ~ temp15;
            temp17 = alt0 ^ temp14;
            alt1 = temp12 ^ temp17;

            plain0 = ((((alt0)) << (13)) | (((alt0)) >> (32 - (13))));
            plain2 = ((((alt2)) << (3)) | (((alt2)) >> (32 - (3))));
            plain1 = alt1 ^ plain0 ^ plain2;
            plain3 = alt3 ^ plain2 ^ (plain0 << 3);
            plain1 = ((((plain1)) << (1)) | (((plain1)) >> (32 - (1))));
            plain3 = ((((plain3)) << (7)) | (((plain3)) >> (32 - (7))));
            plain0 = plain0 ^ plain1 ^ plain3;
            plain2 = plain2 ^ plain3 ^ (plain1 << 7);
            plain0 = ((((plain0)) << (5)) | (((plain0)) >> (32 - (5))));
            plain2 = ((((plain2)) << (22)) | (((plain2)) >> (32 - (22))));
            plain0 ^= _expandedKey[9][0];
            plain1 ^= _expandedKey[9][1];
            plain2 ^= _expandedKey[9][2];
            plain3 ^= _expandedKey[9][3];

            temp01 = plain0 | plain3;
            temp02 = plain2 ^ plain3;
            temp03 = ~ plain1;
            temp04 = plain0 ^ plain2;
            temp05 = plain0 | temp03;
            temp06 = plain3 & temp04;
            temp07 = temp01 & temp02;
            temp08 = plain1 | temp06;
            alt2 = temp02 ^ temp05;
            temp10 = temp07 ^ temp08;
            temp11 = temp01 ^ temp10;
            temp12 = alt2 ^ temp11;
            temp13 = plain1 & plain3;
            alt3 = ~ temp10;
            alt1 = temp13 ^ temp12;
            temp16 = temp10 | alt1;
            temp17 = temp05 & temp16;
            alt0 = plain2 ^ temp17;

            plain0 = ((((alt0)) << (13)) | (((alt0)) >> (32 - (13))));
            plain2 = ((((alt2)) << (3)) | (((alt2)) >> (32 - (3))));
            plain1 = alt1 ^ plain0 ^ plain2;
            plain3 = alt3 ^ plain2 ^ (plain0 << 3);
            plain1 = ((((plain1)) << (1)) | (((plain1)) >> (32 - (1))));
            plain3 = ((((plain3)) << (7)) | (((plain3)) >> (32 - (7))));
            plain0 = plain0 ^ plain1 ^ plain3;
            plain2 = plain2 ^ plain3 ^ (plain1 << 7);
            plain0 = ((((plain0)) << (5)) | (((plain0)) >> (32 - (5))));
            plain2 = ((((plain2)) << (22)) | (((plain2)) >> (32 - (22))));
            plain0 ^= _expandedKey[10][0];
            plain1 ^= _expandedKey[10][1];
            plain2 ^= _expandedKey[10][2];
            plain3 ^= _expandedKey[10][3];

            temp01 = plain0 | plain2;
            temp02 = plain0 ^ plain1;
            temp03 = plain3 ^ temp01;
            alt0 = temp02 ^ temp03;
            temp05 = plain2 ^ alt0;
            temp06 = plain1 ^ temp05;
            temp07 = plain1 | temp05;
            temp08 = temp01 & temp06;
            temp09 = temp03 ^ temp07;
            temp10 = temp02 | temp09;
            alt1 = temp10 ^ temp08;
            temp12 = plain0 | plain3;
            temp13 = temp09 ^ alt1;
            temp14 = plain1 ^ temp13;
            alt3 = ~ temp09;
            alt2 = temp12 ^ temp14;

            plain0 = ((((alt0)) << (13)) | (((alt0)) >> (32 - (13))));
            plain2 = ((((alt2)) << (3)) | (((alt2)) >> (32 - (3))));
            plain1 = alt1 ^ plain0 ^ plain2;
            plain3 = alt3 ^ plain2 ^ (plain0 << 3);
            plain1 = ((((plain1)) << (1)) | (((plain1)) >> (32 - (1))));
            plain3 = ((((plain3)) << (7)) | (((plain3)) >> (32 - (7))));
            plain0 = plain0 ^ plain1 ^ plain3;
            plain2 = plain2 ^ plain3 ^ (plain1 << 7);
            plain0 = ((((plain0)) << (5)) | (((plain0)) >> (32 - (5))));
            plain2 = ((((plain2)) << (22)) | (((plain2)) >> (32 - (22))));
            plain0 ^= _expandedKey[11][0];
            plain1 ^= _expandedKey[11][1];
            plain2 ^= _expandedKey[11][2];
            plain3 ^= _expandedKey[11][3];

            temp01 = plain0 ^ plain2;
            temp02 = plain0 | plain3;
            temp03 = plain0 & plain3;
            temp04 = temp01 & temp02;
            temp05 = plain1 | temp03;
            temp06 = plain0 & plain1;
            temp07 = plain3 ^ temp04;
            temp08 = plain2 | temp06;
            temp09 = plain1 ^ temp07;
            temp10 = plain3 & temp05;
            temp11 = temp02 ^ temp10;
            alt3 = temp08 ^ temp09;
            temp13 = plain3 | alt3;
            temp14 = plain0 | temp07;
            temp15 = plain1 & temp13;
            alt2 = temp08 ^ temp11;
            alt0 = temp14 ^ temp15;
            alt1 = temp05 ^ temp04;

            plain0 = ((((alt0)) << (13)) | (((alt0)) >> (32 - (13))));
            plain2 = ((((alt2)) << (3)) | (((alt2)) >> (32 - (3))));
            plain1 = alt1 ^ plain0 ^ plain2;
            plain3 = alt3 ^ plain2 ^ (plain0 << 3);
            plain1 = ((((plain1)) << (1)) | (((plain1)) >> (32 - (1))));
            plain3 = ((((plain3)) << (7)) | (((plain3)) >> (32 - (7))));
            plain0 = plain0 ^ plain1 ^ plain3;
            plain2 = plain2 ^ plain3 ^ (plain1 << 7);
            plain0 = ((((plain0)) << (5)) | (((plain0)) >> (32 - (5))));
            plain2 = ((((plain2)) << (22)) | (((plain2)) >> (32 - (22))));
            plain0 ^= _expandedKey[12][0];
            plain1 ^= _expandedKey[12][1];
            plain2 ^= _expandedKey[12][2];
            plain3 ^= _expandedKey[12][3];

            temp01 = plain0 | plain1;
            temp02 = plain1 | plain2;
            temp03 = plain0 ^ temp02;
            temp04 = plain1 ^ plain3;
            temp05 = plain3 | temp03;
            temp06 = plain3 & temp01;
            alt3 = temp03 ^ temp06;
            temp08 = alt3 & temp04;
            temp09 = temp04 & temp05;
            temp10 = plain2 ^ temp06;
            temp11 = plain1 & plain2;
            temp12 = temp04 ^ temp08;
            temp13 = temp11 | temp03;
            temp14 = temp10 ^ temp09;
            temp15 = plain0 & temp05;
            temp16 = temp11 | temp12;
            alt2 = temp13 ^ temp08;
            alt1 = temp15 ^ temp16;
            alt0 = ~ temp14;

            plain0 = ((((alt0)) << (13)) | (((alt0)) >> (32 - (13))));
            plain2 = ((((alt2)) << (3)) | (((alt2)) >> (32 - (3))));
            plain1 = alt1 ^ plain0 ^ plain2;
            plain3 = alt3 ^ plain2 ^ (plain0 << 3);
            plain1 = ((((plain1)) << (1)) | (((plain1)) >> (32 - (1))));
            plain3 = ((((plain3)) << (7)) | (((plain3)) >> (32 - (7))));
            plain0 = plain0 ^ plain1 ^ plain3;
            plain2 = plain2 ^ plain3 ^ (plain1 << 7);
            plain0 = ((((plain0)) << (5)) | (((plain0)) >> (32 - (5))));
            plain2 = ((((plain2)) << (22)) | (((plain2)) >> (32 - (22))));
            plain0 ^= _expandedKey[13][0];
            plain1 ^= _expandedKey[13][1];
            plain2 ^= _expandedKey[13][2];
            plain3 ^= _expandedKey[13][3];

            temp01 = plain1 ^ plain3;
            temp02 = plain1 | plain3;
            temp03 = plain0 & temp01;
            temp04 = plain2 ^ temp02;
            temp05 = temp03 ^ temp04;
            alt0 = ~ temp05;
            temp07 = plain0 ^ temp01;
            temp08 = plain3 | alt0;
            temp09 = plain1 | temp05;
            temp10 = plain3 ^ temp08;
            temp11 = plain1 | temp07;
            temp12 = temp03 | alt0;
            temp13 = temp07 | temp10;
            temp14 = temp01 ^ temp11;
            alt2 = temp09 ^ temp13;
            alt1 = temp07 ^ temp08;
            alt3 = temp12 ^ temp14;

            plain0 = ((((alt0)) << (13)) | (((alt0)) >> (32 - (13))));
            plain2 = ((((alt2)) << (3)) | (((alt2)) >> (32 - (3))));
            plain1 = alt1 ^ plain0 ^ plain2;
            plain3 = alt3 ^ plain2 ^ (plain0 << 3);
            plain1 = ((((plain1)) << (1)) | (((plain1)) >> (32 - (1))));
            plain3 = ((((plain3)) << (7)) | (((plain3)) >> (32 - (7))));
            plain0 = plain0 ^ plain1 ^ plain3;
            plain2 = plain2 ^ plain3 ^ (plain1 << 7);
            plain0 = ((((plain0)) << (5)) | (((plain0)) >> (32 - (5))));
            plain2 = ((((plain2)) << (22)) | (((plain2)) >> (32 - (22))));
            plain0 ^= _expandedKey[14][0];
            plain1 ^= _expandedKey[14][1];
            plain2 ^= _expandedKey[14][2];
            plain3 ^= _expandedKey[14][3];

            temp01 = plain0 & plain3;
            temp02 = plain1 ^ plain2;
            temp03 = plain0 ^ plain3;
            temp04 = temp01 ^ temp02;
            temp05 = plain1 | plain2;
            alt1 = ~ temp04;
            temp07 = temp03 & temp05;
            temp08 = plain1 & alt1;
            temp09 = plain0 | plain2;
            temp10 = temp07 ^ temp08;
            temp11 = plain1 | plain3;
            temp12 = plain2 ^ temp11;
            temp13 = temp09 ^ temp10;
            alt2 = ~ temp13;
            temp15 = alt1 & temp03;
            alt3 = temp12 ^ temp07;
            temp17 = plain0 ^ plain1;
            temp18 = alt2 ^ temp15;
            alt0 = temp17 ^ temp18;

            plain0 = ((((alt0)) << (13)) | (((alt0)) >> (32 - (13))));
            plain2 = ((((alt2)) << (3)) | (((alt2)) >> (32 - (3))));
            plain1 = alt1 ^ plain0 ^ plain2;
            plain3 = alt3 ^ plain2 ^ (plain0 << 3);
            plain1 = ((((plain1)) << (1)) | (((plain1)) >> (32 - (1))));
            plain3 = ((((plain3)) << (7)) | (((plain3)) >> (32 - (7))));
            plain0 = plain0 ^ plain1 ^ plain3;
            plain2 = plain2 ^ plain3 ^ (plain1 << 7);
            plain0 = ((((plain0)) << (5)) | (((plain0)) >> (32 - (5))));
            plain2 = ((((plain2)) << (22)) | (((plain2)) >> (32 - (22))));
            plain0 ^= _expandedKey[15][0];
            plain1 ^= _expandedKey[15][1];
            plain2 ^= _expandedKey[15][2];
            plain3 ^= _expandedKey[15][3];

            temp01 = plain0 & plain2;
            temp02 = ~ plain3;
            temp03 = plain0 & temp02;
            temp04 = plain1 | temp01;
            temp05 = plain0 & plain1;
            temp06 = plain2 ^ temp04;
            alt3 = temp03 ^ temp06;
            temp08 = plain2 | alt3;
            temp09 = plain3 | temp05;
            temp10 = plain0 ^ temp08;
            temp11 = temp04 & alt3;
            alt1 = temp09 ^ temp10;
            temp13 = plain1 ^ alt1;
            temp14 = temp01 ^ alt1;
            temp15 = plain2 ^ temp05;
            temp16 = temp11 | temp13;
            temp17 = temp02 | temp14;
            alt0 = temp15 ^ temp17;
            alt2 = plain0 ^ temp16;

            plain0 = ((((alt0)) << (13)) | (((alt0)) >> (32 - (13))));
            plain2 = ((((alt2)) << (3)) | (((alt2)) >> (32 - (3))));
            plain1 = alt1 ^ plain0 ^ plain2;
            plain3 = alt3 ^ plain2 ^ (plain0 << 3);
            plain1 = ((((plain1)) << (1)) | (((plain1)) >> (32 - (1))));
            plain3 = ((((plain3)) << (7)) | (((plain3)) >> (32 - (7))));
            plain0 = plain0 ^ plain1 ^ plain3;
            plain2 = plain2 ^ plain3 ^ (plain1 << 7);
            plain0 = ((((plain0)) << (5)) | (((plain0)) >> (32 - (5))));
            plain2 = ((((plain2)) << (22)) | (((plain2)) >> (32 - (22))));
            plain0 ^= _expandedKey[16][0];
            plain1 ^= _expandedKey[16][1];
            plain2 ^= _expandedKey[16][2];
            plain3 ^= _expandedKey[16][3];

            temp01 = plain1 ^ plain2;
            temp02 = plain0 | plain3;
            temp03 = plain0 ^ plain1;
            alt3 = temp02 ^ temp01;
            temp05 = plain2 | alt3;
            temp06 = plain0 ^ plain3;
            temp07 = plain1 | plain2;
            temp08 = plain3 & temp05;
            temp09 = temp03 & temp07;
            alt2 = temp09 ^ temp08;
            temp11 = temp09 & alt2;
            temp12 = plain2 ^ plain3;
            temp13 = temp07 ^ temp11;
            temp14 = plain1 & temp06;
            temp15 = temp06 ^ temp13;
            alt0 = ~ temp15;
            temp17 = alt0 ^ temp14;
            alt1 = temp12 ^ temp17;

            plain0 = ((((alt0)) << (13)) | (((alt0)) >> (32 - (13))));
            plain2 = ((((alt2)) << (3)) | (((alt2)) >> (32 - (3))));
            plain1 = alt1 ^ plain0 ^ plain2;
            plain3 = alt3 ^ plain2 ^ (plain0 << 3);
            plain1 = ((((plain1)) << (1)) | (((plain1)) >> (32 - (1))));
            plain3 = ((((plain3)) << (7)) | (((plain3)) >> (32 - (7))));
            plain0 = plain0 ^ plain1 ^ plain3;
            plain2 = plain2 ^ plain3 ^ (plain1 << 7);
            plain0 = ((((plain0)) << (5)) | (((plain0)) >> (32 - (5))));
            plain2 = ((((plain2)) << (22)) | (((plain2)) >> (32 - (22))));
            plain0 ^= _expandedKey[17][0];
            plain1 ^= _expandedKey[17][1];
            plain2 ^= _expandedKey[17][2];
            plain3 ^= _expandedKey[17][3];

            temp01 = plain0 | plain3;
            temp02 = plain2 ^ plain3;
            temp03 = ~ plain1;
            temp04 = plain0 ^ plain2;
            temp05 = plain0 | temp03;
            temp06 = plain3 & temp04;
            temp07 = temp01 & temp02;
            temp08 = plain1 | temp06;
            alt2 = temp02 ^ temp05;
            temp10 = temp07 ^ temp08;
            temp11 = temp01 ^ temp10;
            temp12 = alt2 ^ temp11;
            temp13 = plain1 & plain3;
            alt3 = ~ temp10;
            alt1 = temp13 ^ temp12;
            temp16 = temp10 | alt1;
            temp17 = temp05 & temp16;
            alt0 = plain2 ^ temp17;

            plain0 = ((((alt0)) << (13)) | (((alt0)) >> (32 - (13))));
            plain2 = ((((alt2)) << (3)) | (((alt2)) >> (32 - (3))));
            plain1 = alt1 ^ plain0 ^ plain2;
            plain3 = alt3 ^ plain2 ^ (plain0 << 3);
            plain1 = ((((plain1)) << (1)) | (((plain1)) >> (32 - (1))));
            plain3 = ((((plain3)) << (7)) | (((plain3)) >> (32 - (7))));
            plain0 = plain0 ^ plain1 ^ plain3;
            plain2 = plain2 ^ plain3 ^ (plain1 << 7);
            plain0 = ((((plain0)) << (5)) | (((plain0)) >> (32 - (5))));
            plain2 = ((((plain2)) << (22)) | (((plain2)) >> (32 - (22))));
            plain0 ^= _expandedKey[18][0];
            plain1 ^= _expandedKey[18][1];
            plain2 ^= _expandedKey[18][2];
            plain3 ^= _expandedKey[18][3];

            temp01 = plain0 | plain2;
            temp02 = plain0 ^ plain1;
            temp03 = plain3 ^ temp01;
            alt0 = temp02 ^ temp03;
            temp05 = plain2 ^ alt0;
            temp06 = plain1 ^ temp05;
            temp07 = plain1 | temp05;
            temp08 = temp01 & temp06;
            temp09 = temp03 ^ temp07;
            temp10 = temp02 | temp09;
            alt1 = temp10 ^ temp08;
            temp12 = plain0 | plain3;
            temp13 = temp09 ^ alt1;
            temp14 = plain1 ^ temp13;
            alt3 = ~ temp09;
            alt2 = temp12 ^ temp14;

            plain0 = ((((alt0)) << (13)) | (((alt0)) >> (32 - (13))));
            plain2 = ((((alt2)) << (3)) | (((alt2)) >> (32 - (3))));
            plain1 = alt1 ^ plain0 ^ plain2;
            plain3 = alt3 ^ plain2 ^ (plain0 << 3);
            plain1 = ((((plain1)) << (1)) | (((plain1)) >> (32 - (1))));
            plain3 = ((((plain3)) << (7)) | (((plain3)) >> (32 - (7))));
            plain0 = plain0 ^ plain1 ^ plain3;
            plain2 = plain2 ^ plain3 ^ (plain1 << 7);
            plain0 = ((((plain0)) << (5)) | (((plain0)) >> (32 - (5))));
            plain2 = ((((plain2)) << (22)) | (((plain2)) >> (32 - (22))));
            plain0 ^= _expandedKey[19][0];
            plain1 ^= _expandedKey[19][1];
            plain2 ^= _expandedKey[19][2];
            plain3 ^= _expandedKey[19][3];

            temp01 = plain0 ^ plain2;
            temp02 = plain0 | plain3;
            temp03 = plain0 & plain3;
            temp04 = temp01 & temp02;
            temp05 = plain1 | temp03;
            temp06 = plain0 & plain1;
            temp07 = plain3 ^ temp04;
            temp08 = plain2 | temp06;
            temp09 = plain1 ^ temp07;
            temp10 = plain3 & temp05;
            temp11 = temp02 ^ temp10;
            alt3 = temp08 ^ temp09;
            temp13 = plain3 | alt3;
            temp14 = plain0 | temp07;
            temp15 = plain1 & temp13;
            alt2 = temp08 ^ temp11;
            alt0 = temp14 ^ temp15;
            alt1 = temp05 ^ temp04;

            plain0 = ((((alt0)) << (13)) | (((alt0)) >> (32 - (13))));
            plain2 = ((((alt2)) << (3)) | (((alt2)) >> (32 - (3))));
            plain1 = alt1 ^ plain0 ^ plain2;
            plain3 = alt3 ^ plain2 ^ (plain0 << 3);
            plain1 = ((((plain1)) << (1)) | (((plain1)) >> (32 - (1))));
            plain3 = ((((plain3)) << (7)) | (((plain3)) >> (32 - (7))));
            plain0 = plain0 ^ plain1 ^ plain3;
            plain2 = plain2 ^ plain3 ^ (plain1 << 7);
            plain0 = ((((plain0)) << (5)) | (((plain0)) >> (32 - (5))));
            plain2 = ((((plain2)) << (22)) | (((plain2)) >> (32 - (22))));
            plain0 ^= _expandedKey[20][0];
            plain1 ^= _expandedKey[20][1];
            plain2 ^= _expandedKey[20][2];
            plain3 ^= _expandedKey[20][3];

            temp01 = plain0 | plain1;
            temp02 = plain1 | plain2;
            temp03 = plain0 ^ temp02;
            temp04 = plain1 ^ plain3;
            temp05 = plain3 | temp03;
            temp06 = plain3 & temp01;
            alt3 = temp03 ^ temp06;
            temp08 = alt3 & temp04;
            temp09 = temp04 & temp05;
            temp10 = plain2 ^ temp06;
            temp11 = plain1 & plain2;
            temp12 = temp04 ^ temp08;
            temp13 = temp11 | temp03;
            temp14 = temp10 ^ temp09;
            temp15 = plain0 & temp05;
            temp16 = temp11 | temp12;
            alt2 = temp13 ^ temp08;
            alt1 = temp15 ^ temp16;
            alt0 = ~ temp14;

            plain0 = ((((alt0)) << (13)) | (((alt0)) >> (32 - (13))));
            plain2 = ((((alt2)) << (3)) | (((alt2)) >> (32 - (3))));
            plain1 = alt1 ^ plain0 ^ plain2;
            plain3 = alt3 ^ plain2 ^ (plain0 << 3);
            plain1 = ((((plain1)) << (1)) | (((plain1)) >> (32 - (1))));
            plain3 = ((((plain3)) << (7)) | (((plain3)) >> (32 - (7))));
            plain0 = plain0 ^ plain1 ^ plain3;
            plain2 = plain2 ^ plain3 ^ (plain1 << 7);
            plain0 = ((((plain0)) << (5)) | (((plain0)) >> (32 - (5))));
            plain2 = ((((plain2)) << (22)) | (((plain2)) >> (32 - (22))));
            plain0 ^= _expandedKey[21][0];
            plain1 ^= _expandedKey[21][1];
            plain2 ^= _expandedKey[21][2];
            plain3 ^= _expandedKey[21][3];

            temp01 = plain1 ^ plain3;
            temp02 = plain1 | plain3;
            temp03 = plain0 & temp01;
            temp04 = plain2 ^ temp02;
            temp05 = temp03 ^ temp04;
            alt0 = ~ temp05;
            temp07 = plain0 ^ temp01;
            temp08 = plain3 | alt0;
            temp09 = plain1 | temp05;
            temp10 = plain3 ^ temp08;
            temp11 = plain1 | temp07;
            temp12 = temp03 | alt0;
            temp13 = temp07 | temp10;
            temp14 = temp01 ^ temp11;
            alt2 = temp09 ^ temp13;
            alt1 = temp07 ^ temp08;
            alt3 = temp12 ^ temp14;

            plain0 = ((((alt0)) << (13)) | (((alt0)) >> (32 - (13))));
            plain2 = ((((alt2)) << (3)) | (((alt2)) >> (32 - (3))));
            plain1 = alt1 ^ plain0 ^ plain2;
            plain3 = alt3 ^ plain2 ^ (plain0 << 3);
            plain1 = ((((plain1)) << (1)) | (((plain1)) >> (32 - (1))));
            plain3 = ((((plain3)) << (7)) | (((plain3)) >> (32 - (7))));
            plain0 = plain0 ^ plain1 ^ plain3;
            plain2 = plain2 ^ plain3 ^ (plain1 << 7);
            plain0 = ((((plain0)) << (5)) | (((plain0)) >> (32 - (5))));
            plain2 = ((((plain2)) << (22)) | (((plain2)) >> (32 - (22))));
            plain0 ^= _expandedKey[22][0];
            plain1 ^= _expandedKey[22][1];
            plain2 ^= _expandedKey[22][2];
            plain3 ^= _expandedKey[22][3];

            temp01 = plain0 & plain3;
            temp02 = plain1 ^ plain2;
            temp03 = plain0 ^ plain3;
            temp04 = temp01 ^ temp02;
            temp05 = plain1 | plain2;
            alt1 = ~ temp04;
            temp07 = temp03 & temp05;
            temp08 = plain1 & alt1;
            temp09 = plain0 | plain2;
            temp10 = temp07 ^ temp08;
            temp11 = plain1 | plain3;
            temp12 = plain2 ^ temp11;
            temp13 = temp09 ^ temp10;
            alt2 = ~ temp13;
            temp15 = alt1 & temp03;
            alt3 = temp12 ^ temp07;
            temp17 = plain0 ^ plain1;
            temp18 = alt2 ^ temp15;
            alt0 = temp17 ^ temp18;

            plain0 = ((((alt0)) << (13)) | (((alt0)) >> (32 - (13))));
            plain2 = ((((alt2)) << (3)) | (((alt2)) >> (32 - (3))));
            plain1 = alt1 ^ plain0 ^ plain2;
            plain3 = alt3 ^ plain2 ^ (plain0 << 3);
            plain1 = ((((plain1)) << (1)) | (((plain1)) >> (32 - (1))));
            plain3 = ((((plain3)) << (7)) | (((plain3)) >> (32 - (7))));
            plain0 = plain0 ^ plain1 ^ plain3;
            plain2 = plain2 ^ plain3 ^ (plain1 << 7);
            plain0 = ((((plain0)) << (5)) | (((plain0)) >> (32 - (5))));
            plain2 = ((((plain2)) << (22)) | (((plain2)) >> (32 - (22))));
            plain0 ^= _expandedKey[23][0];
            plain1 ^= _expandedKey[23][1];
            plain2 ^= _expandedKey[23][2];
            plain3 ^= _expandedKey[23][3];

            temp01 = plain0 & plain2;
            temp02 = ~ plain3;
            temp03 = plain0 & temp02;
            temp04 = plain1 | temp01;
            temp05 = plain0 & plain1;
            temp06 = plain2 ^ temp04;
            alt3 = temp03 ^ temp06;
            temp08 = plain2 | alt3;
            temp09 = plain3 | temp05;
            temp10 = plain0 ^ temp08;
            temp11 = temp04 & alt3;
            alt1 = temp09 ^ temp10;
            temp13 = plain1 ^ alt1;
            temp14 = temp01 ^ alt1;
            temp15 = plain2 ^ temp05;
            temp16 = temp11 | temp13;
            temp17 = temp02 | temp14;
            alt0 = temp15 ^ temp17;
            alt2 = plain0 ^ temp16;

            plain0 = ((((alt0)) << (13)) | (((alt0)) >> (32 - (13))));
            plain2 = ((((alt2)) << (3)) | (((alt2)) >> (32 - (3))));
            plain1 = alt1 ^ plain0 ^ plain2;
            plain3 = alt3 ^ plain2 ^ (plain0 << 3);
            plain1 = ((((plain1)) << (1)) | (((plain1)) >> (32 - (1))));
            plain3 = ((((plain3)) << (7)) | (((plain3)) >> (32 - (7))));
            plain0 = plain0 ^ plain1 ^ plain3;
            plain2 = plain2 ^ plain3 ^ (plain1 << 7);
            plain0 = ((((plain0)) << (5)) | (((plain0)) >> (32 - (5))));
            plain2 = ((((plain2)) << (22)) | (((plain2)) >> (32 - (22))));
            plain0 ^= _expandedKey[24][0];
            plain1 ^= _expandedKey[24][1];
            plain2 ^= _expandedKey[24][2];
            plain3 ^= _expandedKey[24][3];

            temp01 = plain1 ^ plain2;
            temp02 = plain0 | plain3;
            temp03 = plain0 ^ plain1;
            alt3 = temp02 ^ temp01;
            temp05 = plain2 | alt3;
            temp06 = plain0 ^ plain3;
            temp07 = plain1 | plain2;
            temp08 = plain3 & temp05;
            temp09 = temp03 & temp07;
            alt2 = temp09 ^ temp08;
            temp11 = temp09 & alt2;
            temp12 = plain2 ^ plain3;
            temp13 = temp07 ^ temp11;
            temp14 = plain1 & temp06;
            temp15 = temp06 ^ temp13;
            alt0 = ~ temp15;
            temp17 = alt0 ^ temp14;
            alt1 = temp12 ^ temp17;

            plain0 = ((((alt0)) << (13)) | (((alt0)) >> (32 - (13))));
            plain2 = ((((alt2)) << (3)) | (((alt2)) >> (32 - (3))));
            plain1 = alt1 ^ plain0 ^ plain2;
            plain3 = alt3 ^ plain2 ^ (plain0 << 3);
            plain1 = ((((plain1)) << (1)) | (((plain1)) >> (32 - (1))));
            plain3 = ((((plain3)) << (7)) | (((plain3)) >> (32 - (7))));
            plain0 = plain0 ^ plain1 ^ plain3;
            plain2 = plain2 ^ plain3 ^ (plain1 << 7);
            plain0 = ((((plain0)) << (5)) | (((plain0)) >> (32 - (5))));
            plain2 = ((((plain2)) << (22)) | (((plain2)) >> (32 - (22))));
            plain0 ^= _expandedKey[25][0];
            plain1 ^= _expandedKey[25][1];
            plain2 ^= _expandedKey[25][2];
            plain3 ^= _expandedKey[25][3];

            temp01 = plain0 | plain3;
            temp02 = plain2 ^ plain3;
            temp03 = ~ plain1;
            temp04 = plain0 ^ plain2;
            temp05 = plain0 | temp03;
            temp06 = plain3 & temp04;
            temp07 = temp01 & temp02;
            temp08 = plain1 | temp06;
            alt2 = temp02 ^ temp05;
            temp10 = temp07 ^ temp08;
            temp11 = temp01 ^ temp10;
            temp12 = alt2 ^ temp11;
            temp13 = plain1 & plain3;
            alt3 = ~ temp10;
            alt1 = temp13 ^ temp12;
            temp16 = temp10 | alt1;
            temp17 = temp05 & temp16;
            alt0 = plain2 ^ temp17;

            plain0 = ((((alt0)) << (13)) | (((alt0)) >> (32 - (13))));
            plain2 = ((((alt2)) << (3)) | (((alt2)) >> (32 - (3))));
            plain1 = alt1 ^ plain0 ^ plain2;
            plain3 = alt3 ^ plain2 ^ (plain0 << 3);
            plain1 = ((((plain1)) << (1)) | (((plain1)) >> (32 - (1))));
            plain3 = ((((plain3)) << (7)) | (((plain3)) >> (32 - (7))));
            plain0 = plain0 ^ plain1 ^ plain3;
            plain2 = plain2 ^ plain3 ^ (plain1 << 7);
            plain0 = ((((plain0)) << (5)) | (((plain0)) >> (32 - (5))));
            plain2 = ((((plain2)) << (22)) | (((plain2)) >> (32 - (22))));
            plain0 ^= _expandedKey[26][0];
            plain1 ^= _expandedKey[26][1];
            plain2 ^= _expandedKey[26][2];
            plain3 ^= _expandedKey[26][3];

            temp01 = plain0 | plain2;
            temp02 = plain0 ^ plain1;
            temp03 = plain3 ^ temp01;
            alt0 = temp02 ^ temp03;
            temp05 = plain2 ^ alt0;
            temp06 = plain1 ^ temp05;
            temp07 = plain1 | temp05;
            temp08 = temp01 & temp06;
            temp09 = temp03 ^ temp07;
            temp10 = temp02 | temp09;
            alt1 = temp10 ^ temp08;
            temp12 = plain0 | plain3;
            temp13 = temp09 ^ alt1;
            temp14 = plain1 ^ temp13;
            alt3 = ~ temp09;
            alt2 = temp12 ^ temp14;

            plain0 = ((((alt0)) << (13)) | (((alt0)) >> (32 - (13))));
            plain2 = ((((alt2)) << (3)) | (((alt2)) >> (32 - (3))));
            plain1 = alt1 ^ plain0 ^ plain2;
            plain3 = alt3 ^ plain2 ^ (plain0 << 3);
            plain1 = ((((plain1)) << (1)) | (((plain1)) >> (32 - (1))));
            plain3 = ((((plain3)) << (7)) | (((plain3)) >> (32 - (7))));
            plain0 = plain0 ^ plain1 ^ plain3;
            plain2 = plain2 ^ plain3 ^ (plain1 << 7);
            plain0 = ((((plain0)) << (5)) | (((plain0)) >> (32 - (5))));
            plain2 = ((((plain2)) << (22)) | (((plain2)) >> (32 - (22))));
            plain0 ^= _expandedKey[27][0];
            plain1 ^= _expandedKey[27][1];
            plain2 ^= _expandedKey[27][2];
            plain3 ^= _expandedKey[27][3];

            temp01 = plain0 ^ plain2;
            temp02 = plain0 | plain3;
            temp03 = plain0 & plain3;
            temp04 = temp01 & temp02;
            temp05 = plain1 | temp03;
            temp06 = plain0 & plain1;
            temp07 = plain3 ^ temp04;
            temp08 = plain2 | temp06;
            temp09 = plain1 ^ temp07;
            temp10 = plain3 & temp05;
            temp11 = temp02 ^ temp10;
            alt3 = temp08 ^ temp09;
            temp13 = plain3 | alt3;
            temp14 = plain0 | temp07;
            temp15 = plain1 & temp13;
            alt2 = temp08 ^ temp11;
            alt0 = temp14 ^ temp15;
            alt1 = temp05 ^ temp04;

            plain0 = ((((alt0)) << (13)) | (((alt0)) >> (32 - (13))));
            plain2 = ((((alt2)) << (3)) | (((alt2)) >> (32 - (3))));
            plain1 = alt1 ^ plain0 ^ plain2;
            plain3 = alt3 ^ plain2 ^ (plain0 << 3);
            plain1 = ((((plain1)) << (1)) | (((plain1)) >> (32 - (1))));
            plain3 = ((((plain3)) << (7)) | (((plain3)) >> (32 - (7))));
            plain0 = plain0 ^ plain1 ^ plain3;
            plain2 = plain2 ^ plain3 ^ (plain1 << 7);
            plain0 = ((((plain0)) << (5)) | (((plain0)) >> (32 - (5))));
            plain2 = ((((plain2)) << (22)) | (((plain2)) >> (32 - (22))));
            plain0 ^= _expandedKey[28][0];
            plain1 ^= _expandedKey[28][1];
            plain2 ^= _expandedKey[28][2];
            plain3 ^= _expandedKey[28][3];

            temp01 = plain0 | plain1;
            temp02 = plain1 | plain2;
            temp03 = plain0 ^ temp02;
            temp04 = plain1 ^ plain3;
            temp05 = plain3 | temp03;
            temp06 = plain3 & temp01;
            alt3 = temp03 ^ temp06;
            temp08 = alt3 & temp04;
            temp09 = temp04 & temp05;
            temp10 = plain2 ^ temp06;
            temp11 = plain1 & plain2;
            temp12 = temp04 ^ temp08;
            temp13 = temp11 | temp03;
            temp14 = temp10 ^ temp09;
            temp15 = plain0 & temp05;
            temp16 = temp11 | temp12;
            alt2 = temp13 ^ temp08;
            alt1 = temp15 ^ temp16;
            alt0 = ~ temp14;

            plain0 = ((((alt0)) << (13)) | (((alt0)) >> (32 - (13))));
            plain2 = ((((alt2)) << (3)) | (((alt2)) >> (32 - (3))));
            plain1 = alt1 ^ plain0 ^ plain2;
            plain3 = alt3 ^ plain2 ^ (plain0 << 3);
            plain1 = ((((plain1)) << (1)) | (((plain1)) >> (32 - (1))));
            plain3 = ((((plain3)) << (7)) | (((plain3)) >> (32 - (7))));
            plain0 = plain0 ^ plain1 ^ plain3;
            plain2 = plain2 ^ plain3 ^ (plain1 << 7);
            plain0 = ((((plain0)) << (5)) | (((plain0)) >> (32 - (5))));
            plain2 = ((((plain2)) << (22)) | (((plain2)) >> (32 - (22))));
            plain0 ^= _expandedKey[29][0];
            plain1 ^= _expandedKey[29][1];
            plain2 ^= _expandedKey[29][2];
            plain3 ^= _expandedKey[29][3];

            temp01 = plain1 ^ plain3;
            temp02 = plain1 | plain3;
            temp03 = plain0 & temp01;
            temp04 = plain2 ^ temp02;
            temp05 = temp03 ^ temp04;
            alt0 = ~ temp05;
            temp07 = plain0 ^ temp01;
            temp08 = plain3 | alt0;
            temp09 = plain1 | temp05;
            temp10 = plain3 ^ temp08;
            temp11 = plain1 | temp07;
            temp12 = temp03 | alt0;
            temp13 = temp07 | temp10;
            temp14 = temp01 ^ temp11;
            alt2 = temp09 ^ temp13;
            alt1 = temp07 ^ temp08;
            alt3 = temp12 ^ temp14;

            plain0 = ((((alt0)) << (13)) | (((alt0)) >> (32 - (13))));
            plain2 = ((((alt2)) << (3)) | (((alt2)) >> (32 - (3))));
            plain1 = alt1 ^ plain0 ^ plain2;
            plain3 = alt3 ^ plain2 ^ (plain0 << 3);
            plain1 = ((((plain1)) << (1)) | (((plain1)) >> (32 - (1))));
            plain3 = ((((plain3)) << (7)) | (((plain3)) >> (32 - (7))));
            plain0 = plain0 ^ plain1 ^ plain3;
            plain2 = plain2 ^ plain3 ^ (plain1 << 7);
            plain0 = ((((plain0)) << (5)) | (((plain0)) >> (32 - (5))));
            plain2 = ((((plain2)) << (22)) | (((plain2)) >> (32 - (22))));
            plain0 ^= _expandedKey[30][0];
            plain1 ^= _expandedKey[30][1];
            plain2 ^= _expandedKey[30][2];
            plain3 ^= _expandedKey[30][3];

            temp01 = plain0 & plain3;
            temp02 = plain1 ^ plain2;
            temp03 = plain0 ^ plain3;
            temp04 = temp01 ^ temp02;
            temp05 = plain1 | plain2;
            alt1 = ~ temp04;
            temp07 = temp03 & temp05;
            temp08 = plain1 & alt1;
            temp09 = plain0 | plain2;
            temp10 = temp07 ^ temp08;
            temp11 = plain1 | plain3;
            temp12 = plain2 ^ temp11;
            temp13 = temp09 ^ temp10;
            alt2 = ~ temp13;
            temp15 = alt1 & temp03;
            alt3 = temp12 ^ temp07;
            temp17 = plain0 ^ plain1;
            temp18 = alt2 ^ temp15;
            alt0 = temp17 ^ temp18;

            plain0 = ((((alt0)) << (13)) | (((alt0)) >> (32 - (13))));
            plain2 = ((((alt2)) << (3)) | (((alt2)) >> (32 - (3))));
            plain1 = alt1 ^ plain0 ^ plain2;
            plain3 = alt3 ^ plain2 ^ (plain0 << 3);
            plain1 = ((((plain1)) << (1)) | (((plain1)) >> (32 - (1))));
            plain3 = ((((plain3)) << (7)) | (((plain3)) >> (32 - (7))));
            plain0 = plain0 ^ plain1 ^ plain3;
            plain2 = plain2 ^ plain3 ^ (plain1 << 7);
            plain0 = ((((plain0)) << (5)) | (((plain0)) >> (32 - (5))));
            plain2 = ((((plain2)) << (22)) | (((plain2)) >> (32 - (22))));
            plain0 ^= _expandedKey[31][0];
            plain1 ^= _expandedKey[31][1];
            plain2 ^= _expandedKey[31][2];
            plain3 ^= _expandedKey[31][3];

            temp01 = plain0 & plain2;
            temp02 = ~ plain3;
            temp03 = plain0 & temp02;
            temp04 = plain1 | temp01;
            temp05 = plain0 & plain1;
            temp06 = plain2 ^ temp04;
            alt3 = temp03 ^ temp06;
            temp08 = plain2 | alt3;
            temp09 = plain3 | temp05;
            temp10 = plain0 ^ temp08;
            temp11 = temp04 & alt3;
            alt1 = temp09 ^ temp10;
            temp13 = plain1 ^ alt1;
            temp14 = temp01 ^ alt1;
            temp15 = plain2 ^ temp05;
            temp16 = temp11 | temp13;
            temp17 = temp02 | temp14;
            alt0 = temp15 ^ temp17;
            alt2 = plain0 ^ temp16;

            plain[0] = alt0 ^ _expandedKey[32][0];
            plain[1] = alt1 ^ _expandedKey[32][1];
            plain[2] = alt2 ^ _expandedKey[32][2];
            plain[3] = alt3 ^ _expandedKey[32][3];
        }

        /// <summary>
        /// Performs the decryption transformation on a block of bytes that
        /// have been translated into words using the big endian convention.
        /// </summary>
        /// <param name="cipher">
        /// The words to decrypt.
        /// </param>
        [CLSCompliant(false)]
        protected internal override void Decrypt(uint[] cipher)
        {
            uint cipher0 = cipher[0] ^ _expandedKey[32][0];
            uint cipher1 = cipher[1] ^ _expandedKey[32][1];
            uint cipher2 = cipher[2] ^ _expandedKey[32][2];
            uint cipher3 = cipher[3] ^ _expandedKey[32][3];

            uint temp01 = cipher0 & cipher1;
            uint temp02 = cipher0 | cipher1;
            uint temp03 = cipher2 | temp01;
            uint temp04 = cipher3 & temp02;
            uint alt3 = temp03 ^ temp04;
            uint temp06 = cipher1 ^ temp04;
            uint temp07 = cipher3 ^ alt3;
            uint temp08 = ~ temp07;
            uint temp09 = temp06 | temp08;
            uint temp10 = cipher1 ^ cipher3;
            uint temp11 = cipher0 | cipher3;
            uint alt1 = cipher0 ^ temp09;
            uint temp13 = cipher2 ^ temp06;
            uint temp14 = cipher2 & temp11;
            uint temp15 = cipher3 | alt1;
            uint temp16 = temp01 | temp10;
            uint alt0 = temp13 ^ temp15;
            uint alt2 = temp14 ^ temp16;

            alt0 ^= _expandedKey[31][0];
            alt1 ^= _expandedKey[31][1];
            alt2 ^= _expandedKey[31][2];
            alt3 ^= _expandedKey[31][3];
            cipher2 = ((((alt2)) << (32 - (22))) | (((alt2)) >> (22)));
            cipher0 = ((((alt0)) << (32 - (5))) | (((alt0)) >> (5)));
            cipher2 = cipher2 ^ alt3 ^ (alt1 << 7);
            cipher0 = cipher0 ^ alt1 ^ alt3;
            cipher3 = ((((alt3)) << (32 - (7))) | (((alt3)) >> (7)));
            cipher1 = ((((alt1)) << (32 - (1))) | (((alt1)) >> (1)));
            cipher3 = cipher3 ^ cipher2 ^ (cipher0) << 3;
            cipher1 = cipher1 ^ cipher0 ^ cipher2;
            cipher2 = ((((cipher2)) << (32 - (3))) | (((cipher2)) >> (3)));
            cipher0 = ((((cipher0)) << (32 - (13))) | (((cipher0)) >> (13)));

            temp01 = cipher0 ^ cipher2;
            temp02 = ~ cipher2;
            temp03 = cipher1 & temp01;
            temp04 = cipher1 | temp02;
            uint temp05 = cipher3 | temp03;
            temp06 = cipher1 ^ cipher3;
            temp07 = cipher0 & temp04;
            temp08 = cipher0 | temp02;
            temp09 = temp07 ^ temp05;
            alt1 = temp06 ^ temp08;
            alt0 = ~ temp09;
            uint temp12 = cipher1 & alt0;
            temp13 = temp01 & temp05;
            temp14 = temp01 ^ temp12;
            temp15 = temp07 ^ temp13;
            temp16 = cipher3 | temp02;
            uint temp17 = cipher0 ^ alt1;
            alt3 = temp17 ^ temp15;
            alt2 = temp16 ^ temp14;

            alt0 ^= _expandedKey[30][0];
            alt1 ^= _expandedKey[30][1];
            alt2 ^= _expandedKey[30][2];
            alt3 ^= _expandedKey[30][3];
            cipher2 = ((((alt2)) << (32 - (22))) | (((alt2)) >> (22)));
            cipher0 = ((((alt0)) << (32 - (5))) | (((alt0)) >> (5)));
            cipher2 = cipher2 ^ alt3 ^ (alt1 << 7);
            cipher0 = cipher0 ^ alt1 ^ alt3;
            cipher3 = ((((alt3)) << (32 - (7))) | (((alt3)) >> (7)));
            cipher1 = ((((alt1)) << (32 - (1))) | (((alt1)) >> (1)));
            cipher3 = cipher3 ^ cipher2 ^ (cipher0) << 3;
            cipher1 = cipher1 ^ cipher0 ^ cipher2;
            cipher2 = ((((cipher2)) << (32 - (3))) | (((cipher2)) >> (3)));
            cipher0 = ((((cipher0)) << (32 - (13))) | (((cipher0)) >> (13)));

            temp01 = cipher0 & cipher3;
            temp02 = cipher2 ^ temp01;
            temp03 = cipher0 ^ cipher3;
            temp04 = cipher1 & temp02;
            temp05 = cipher0 & cipher2;
            alt0 = temp03 ^ temp04;
            temp07 = cipher0 & alt0;
            temp08 = temp01 ^ alt0;
            temp09 = cipher1 | temp05;
            temp10 = ~ cipher1;
            alt1 = temp08 ^ temp09;
            temp12 = temp10 | temp07;
            temp13 = alt0 | alt1;
            alt3 = temp02 ^ temp12;
            temp15 = temp02 ^ temp13;
            temp16 = cipher1 ^ cipher3;
            alt2 = temp16 ^ temp15;

            alt0 ^= _expandedKey[29][0];
            alt1 ^= _expandedKey[29][1];
            alt2 ^= _expandedKey[29][2];
            alt3 ^= _expandedKey[29][3];
            cipher2 = ((((alt2)) << (32 - (22))) | (((alt2)) >> (22)));
            cipher0 = ((((alt0)) << (32 - (5))) | (((alt0)) >> (5)));
            cipher2 = cipher2 ^ alt3 ^ (alt1 << 7);
            cipher0 = cipher0 ^ alt1 ^ alt3;
            cipher3 = ((((alt3)) << (32 - (7))) | (((alt3)) >> (7)));
            cipher1 = ((((alt1)) << (32 - (1))) | (((alt1)) >> (1)));
            cipher3 = cipher3 ^ cipher2 ^ (cipher0) << 3;
            cipher1 = cipher1 ^ cipher0 ^ cipher2;
            cipher2 = ((((cipher2)) << (32 - (3))) | (((cipher2)) >> (3)));
            cipher0 = ((((cipher0)) << (32 - (13))) | (((cipher0)) >> (13)));

            temp01 = cipher1 | cipher3;
            temp02 = cipher2 | cipher3;
            temp03 = cipher0 & temp01;
            temp04 = cipher1 ^ temp02;
            temp05 = cipher2 ^ cipher3;
            temp06 = ~ temp03;
            temp07 = cipher0 & temp04;
            alt1 = temp05 ^ temp07;
            temp09 = alt1 | temp06;
            temp10 = cipher0 ^ temp07;
            temp11 = temp01 ^ temp09;
            temp12 = cipher3 ^ temp04;
            temp13 = cipher2 | temp10;
            alt3 = temp03 ^ temp12;
            temp15 = cipher0 ^ temp04;
            alt2 = temp11 ^ temp13;
            alt0 = temp15 ^ temp09;

            alt0 ^= _expandedKey[28][0];
            alt1 ^= _expandedKey[28][1];
            alt2 ^= _expandedKey[28][2];
            alt3 ^= _expandedKey[28][3];
            cipher2 = ((((alt2)) << (32 - (22))) | (((alt2)) >> (22)));
            cipher0 = ((((alt0)) << (32 - (5))) | (((alt0)) >> (5)));
            cipher2 = cipher2 ^ alt3 ^ (alt1 << 7);
            cipher0 = cipher0 ^ alt1 ^ alt3;
            cipher3 = ((((alt3)) << (32 - (7))) | (((alt3)) >> (7)));
            cipher1 = ((((alt1)) << (32 - (1))) | (((alt1)) >> (1)));
            cipher3 = cipher3 ^ cipher2 ^ (cipher0) << 3;
            cipher1 = cipher1 ^ cipher0 ^ cipher2;
            cipher2 = ((((cipher2)) << (32 - (3))) | (((cipher2)) >> (3)));
            cipher0 = ((((cipher0)) << (32 - (13))) | (((cipher0)) >> (13)));

            temp01 = cipher2 | cipher3;
            temp02 = cipher0 | cipher3;
            temp03 = cipher2 ^ temp02;
            temp04 = cipher1 ^ temp02;
            temp05 = cipher0 ^ cipher3;
            temp06 = temp04 & temp03;
            temp07 = cipher1 & temp01;
            alt2 = temp05 ^ temp06;
            temp09 = cipher0 ^ temp03;
            alt0 = temp07 ^ temp03;
            temp11 = alt0 | temp05;
            temp12 = temp09 & temp11;
            temp13 = cipher0 & alt2;
            temp14 = temp01 ^ temp05;
            alt1 = cipher1 ^ temp12;
            temp16 = cipher1 | temp13;
            alt3 = temp14 ^ temp16;

            alt0 ^= _expandedKey[27][0];
            alt1 ^= _expandedKey[27][1];
            alt2 ^= _expandedKey[27][2];
            alt3 ^= _expandedKey[27][3];
            cipher2 = ((((alt2)) << (32 - (22))) | (((alt2)) >> (22)));
            cipher0 = ((((alt0)) << (32 - (5))) | (((alt0)) >> (5)));
            cipher2 = cipher2 ^ alt3 ^ (alt1 << 7);
            cipher0 = cipher0 ^ alt1 ^ alt3;
            cipher3 = ((((alt3)) << (32 - (7))) | (((alt3)) >> (7)));
            cipher1 = ((((alt1)) << (32 - (1))) | (((alt1)) >> (1)));
            cipher3 = cipher3 ^ cipher2 ^ (cipher0) << 3;
            cipher1 = cipher1 ^ cipher0 ^ cipher2;
            cipher2 = ((((cipher2)) << (32 - (3))) | (((cipher2)) >> (3)));
            cipher0 = ((((cipher0)) << (32 - (13))) | (((cipher0)) >> (13)));

            temp01 = cipher0 ^ cipher3;
            temp02 = cipher2 ^ cipher3;
            temp03 = cipher0 & cipher2;
            temp04 = cipher1 | temp02;
            alt0 = temp01 ^ temp04;
            temp06 = cipher0 | cipher2;
            temp07 = cipher3 | alt0;
            temp08 = ~ cipher3;
            temp09 = cipher1 & temp06;
            temp10 = temp08 | temp03;
            temp11 = cipher1 & temp07;
            temp12 = temp06 & temp02;
            alt3 = temp09 ^ temp10;
            alt1 = temp12 ^ temp11;
            temp15 = cipher2 & alt3;
            temp16 = alt0 ^ alt1;
            temp17 = temp10 ^ temp15;
            alt2 = temp16 ^ temp17;

            alt0 ^= _expandedKey[26][0];
            alt1 ^= _expandedKey[26][1];
            alt2 ^= _expandedKey[26][2];
            alt3 ^= _expandedKey[26][3];
            cipher2 = ((((alt2)) << (32 - (22))) | (((alt2)) >> (22)));
            cipher0 = ((((alt0)) << (32 - (5))) | (((alt0)) >> (5)));
            cipher2 = cipher2 ^ alt3 ^ (alt1 << 7);
            cipher0 = cipher0 ^ alt1 ^ alt3;
            cipher3 = ((((alt3)) << (32 - (7))) | (((alt3)) >> (7)));
            cipher1 = ((((alt1)) << (32 - (1))) | (((alt1)) >> (1)));
            cipher3 = cipher3 ^ cipher2 ^ (cipher0) << 3;
            cipher1 = cipher1 ^ cipher0 ^ cipher2;
            cipher2 = ((((cipher2)) << (32 - (3))) | (((cipher2)) >> (3)));
            cipher0 = ((((cipher0)) << (32 - (13))) | (((cipher0)) >> (13)));

            temp01 = cipher0 ^ cipher1;
            temp02 = cipher1 | cipher3;
            temp03 = cipher0 & cipher2;
            temp04 = cipher2 ^ temp02;
            temp05 = cipher0 | temp04;
            temp06 = temp01 & temp05;
            temp07 = cipher3 | temp03;
            temp08 = cipher1 ^ temp06;
            temp09 = temp07 ^ temp06;
            temp10 = temp04 | temp03;
            temp11 = cipher3 & temp08;
            alt2 = ~ temp09;
            alt1 = temp10 ^ temp11;
            temp14 = cipher0 | alt2;
            temp15 = temp06 ^ alt1;
            alt3 = temp01 ^ temp04;
            temp17 = cipher2 ^ temp15;
            alt0 = temp14 ^ temp17;

            alt0 ^= _expandedKey[25][0];
            alt1 ^= _expandedKey[25][1];
            alt2 ^= _expandedKey[25][2];
            alt3 ^= _expandedKey[25][3];
            cipher2 = ((((alt2)) << (32 - (22))) | (((alt2)) >> (22)));
            cipher0 = ((((alt0)) << (32 - (5))) | (((alt0)) >> (5)));
            cipher2 = cipher2 ^ alt3 ^ (alt1 << 7);
            cipher0 = cipher0 ^ alt1 ^ alt3;
            cipher3 = ((((alt3)) << (32 - (7))) | (((alt3)) >> (7)));
            cipher1 = ((((alt1)) << (32 - (1))) | (((alt1)) >> (1)));
            cipher3 = cipher3 ^ cipher2 ^ (cipher0) << 3;
            cipher1 = cipher1 ^ cipher0 ^ cipher2;
            cipher2 = ((((cipher2)) << (32 - (3))) | (((cipher2)) >> (3)));
            cipher0 = ((((cipher0)) << (32 - (13))) | (((cipher0)) >> (13)));

            temp01 = cipher2 ^ cipher3;
            temp02 = cipher0 | cipher1;
            temp03 = cipher1 | cipher2;
            temp04 = cipher2 & temp01;
            temp05 = temp02 ^ temp01;
            temp06 = cipher0 | temp04;
            alt2 = ~ temp05;
            temp08 = cipher1 ^ cipher3;
            temp09 = temp03 & temp08;
            temp10 = cipher3 | alt2;
            alt1 = temp09 ^ temp06;
            temp12 = cipher0 | temp05;
            temp13 = alt1 ^ temp12;
            temp14 = temp03 ^ temp10;
            temp15 = cipher0 ^ cipher2;
            alt3 = temp14 ^ temp13;
            temp17 = temp05 & temp13;
            uint temp18 = temp14 | temp17;
            alt0 = temp15 ^ temp18;

            alt0 ^= _expandedKey[24][0];
            alt1 ^= _expandedKey[24][1];
            alt2 ^= _expandedKey[24][2];
            alt3 ^= _expandedKey[24][3];
            cipher2 = ((((alt2)) << (32 - (22))) | (((alt2)) >> (22)));
            cipher0 = ((((alt0)) << (32 - (5))) | (((alt0)) >> (5)));
            cipher2 = cipher2 ^ alt3 ^ (alt1 << 7);
            cipher0 = cipher0 ^ alt1 ^ alt3;
            cipher3 = ((((alt3)) << (32 - (7))) | (((alt3)) >> (7)));
            cipher1 = ((((alt1)) << (32 - (1))) | (((alt1)) >> (1)));
            cipher3 = cipher3 ^ cipher2 ^ (cipher0) << 3;
            cipher1 = cipher1 ^ cipher0 ^ cipher2;
            cipher2 = ((((cipher2)) << (32 - (3))) | (((cipher2)) >> (3)));
            cipher0 = ((((cipher0)) << (32 - (13))) | (((cipher0)) >> (13)));

            temp01 = cipher0 & cipher1;
            temp02 = cipher0 | cipher1;
            temp03 = cipher2 | temp01;
            temp04 = cipher3 & temp02;
            alt3 = temp03 ^ temp04;
            temp06 = cipher1 ^ temp04;
            temp07 = cipher3 ^ alt3;
            temp08 = ~ temp07;
            temp09 = temp06 | temp08;
            temp10 = cipher1 ^ cipher3;
            temp11 = cipher0 | cipher3;
            alt1 = cipher0 ^ temp09;
            temp13 = cipher2 ^ temp06;
            temp14 = cipher2 & temp11;
            temp15 = cipher3 | alt1;
            temp16 = temp01 | temp10;
            alt0 = temp13 ^ temp15;
            alt2 = temp14 ^ temp16;

            alt0 ^= _expandedKey[23][0];
            alt1 ^= _expandedKey[23][1];
            alt2 ^= _expandedKey[23][2];
            alt3 ^= _expandedKey[23][3];
            cipher2 = ((((alt2)) << (32 - (22))) | (((alt2)) >> (22)));
            cipher0 = ((((alt0)) << (32 - (5))) | (((alt0)) >> (5)));
            cipher2 = cipher2 ^ alt3 ^ (alt1 << 7);
            cipher0 = cipher0 ^ alt1 ^ alt3;
            cipher3 = ((((alt3)) << (32 - (7))) | (((alt3)) >> (7)));
            cipher1 = ((((alt1)) << (32 - (1))) | (((alt1)) >> (1)));
            cipher3 = cipher3 ^ cipher2 ^ (cipher0) << 3;
            cipher1 = cipher1 ^ cipher0 ^ cipher2;
            cipher2 = ((((cipher2)) << (32 - (3))) | (((cipher2)) >> (3)));
            cipher0 = ((((cipher0)) << (32 - (13))) | (((cipher0)) >> (13)));

            temp01 = cipher0 ^ cipher2;
            temp02 = ~ cipher2;
            temp03 = cipher1 & temp01;
            temp04 = cipher1 | temp02;
            temp05 = cipher3 | temp03;
            temp06 = cipher1 ^ cipher3;
            temp07 = cipher0 & temp04;
            temp08 = cipher0 | temp02;
            temp09 = temp07 ^ temp05;
            alt1 = temp06 ^ temp08;
            alt0 = ~ temp09;
            temp12 = cipher1 & alt0;
            temp13 = temp01 & temp05;
            temp14 = temp01 ^ temp12;
            temp15 = temp07 ^ temp13;
            temp16 = cipher3 | temp02;
            temp17 = cipher0 ^ alt1;
            alt3 = temp17 ^ temp15;
            alt2 = temp16 ^ temp14;

            alt0 ^= _expandedKey[22][0];
            alt1 ^= _expandedKey[22][1];
            alt2 ^= _expandedKey[22][2];
            alt3 ^= _expandedKey[22][3];
            cipher2 = ((((alt2)) << (32 - (22))) | (((alt2)) >> (22)));
            cipher0 = ((((alt0)) << (32 - (5))) | (((alt0)) >> (5)));
            cipher2 = cipher2 ^ alt3 ^ (alt1 << 7);
            cipher0 = cipher0 ^ alt1 ^ alt3;
            cipher3 = ((((alt3)) << (32 - (7))) | (((alt3)) >> (7)));
            cipher1 = ((((alt1)) << (32 - (1))) | (((alt1)) >> (1)));
            cipher3 = cipher3 ^ cipher2 ^ (cipher0) << 3;
            cipher1 = cipher1 ^ cipher0 ^ cipher2;
            cipher2 = ((((cipher2)) << (32 - (3))) | (((cipher2)) >> (3)));
            cipher0 = ((((cipher0)) << (32 - (13))) | (((cipher0)) >> (13)));

            temp01 = cipher0 & cipher3;
            temp02 = cipher2 ^ temp01;
            temp03 = cipher0 ^ cipher3;
            temp04 = cipher1 & temp02;
            temp05 = cipher0 & cipher2;
            alt0 = temp03 ^ temp04;
            temp07 = cipher0 & alt0;
            temp08 = temp01 ^ alt0;
            temp09 = cipher1 | temp05;
            temp10 = ~ cipher1;
            alt1 = temp08 ^ temp09;
            temp12 = temp10 | temp07;
            temp13 = alt0 | alt1;
            alt3 = temp02 ^ temp12;
            temp15 = temp02 ^ temp13;
            temp16 = cipher1 ^ cipher3;
            alt2 = temp16 ^ temp15;

            alt0 ^= _expandedKey[21][0];
            alt1 ^= _expandedKey[21][1];
            alt2 ^= _expandedKey[21][2];
            alt3 ^= _expandedKey[21][3];
            cipher2 = ((((alt2)) << (32 - (22))) | (((alt2)) >> (22)));
            cipher0 = ((((alt0)) << (32 - (5))) | (((alt0)) >> (5)));
            cipher2 = cipher2 ^ alt3 ^ (alt1 << 7);
            cipher0 = cipher0 ^ alt1 ^ alt3;
            cipher3 = ((((alt3)) << (32 - (7))) | (((alt3)) >> (7)));
            cipher1 = ((((alt1)) << (32 - (1))) | (((alt1)) >> (1)));
            cipher3 = cipher3 ^ cipher2 ^ (cipher0) << 3;
            cipher1 = cipher1 ^ cipher0 ^ cipher2;
            cipher2 = ((((cipher2)) << (32 - (3))) | (((cipher2)) >> (3)));
            cipher0 = ((((cipher0)) << (32 - (13))) | (((cipher0)) >> (13)));

            temp01 = cipher1 | cipher3;
            temp02 = cipher2 | cipher3;
            temp03 = cipher0 & temp01;
            temp04 = cipher1 ^ temp02;
            temp05 = cipher2 ^ cipher3;
            temp06 = ~ temp03;
            temp07 = cipher0 & temp04;
            alt1 = temp05 ^ temp07;
            temp09 = alt1 | temp06;
            temp10 = cipher0 ^ temp07;
            temp11 = temp01 ^ temp09;
            temp12 = cipher3 ^ temp04;
            temp13 = cipher2 | temp10;
            alt3 = temp03 ^ temp12;
            temp15 = cipher0 ^ temp04;
            alt2 = temp11 ^ temp13;
            alt0 = temp15 ^ temp09;

            alt0 ^= _expandedKey[20][0];
            alt1 ^= _expandedKey[20][1];
            alt2 ^= _expandedKey[20][2];
            alt3 ^= _expandedKey[20][3];
            cipher2 = ((((alt2)) << (32 - (22))) | (((alt2)) >> (22)));
            cipher0 = ((((alt0)) << (32 - (5))) | (((alt0)) >> (5)));
            cipher2 = cipher2 ^ alt3 ^ (alt1 << 7);
            cipher0 = cipher0 ^ alt1 ^ alt3;
            cipher3 = ((((alt3)) << (32 - (7))) | (((alt3)) >> (7)));
            cipher1 = ((((alt1)) << (32 - (1))) | (((alt1)) >> (1)));
            cipher3 = cipher3 ^ cipher2 ^ (cipher0) << 3;
            cipher1 = cipher1 ^ cipher0 ^ cipher2;
            cipher2 = ((((cipher2)) << (32 - (3))) | (((cipher2)) >> (3)));
            cipher0 = ((((cipher0)) << (32 - (13))) | (((cipher0)) >> (13)));

            temp01 = cipher2 | cipher3;
            temp02 = cipher0 | cipher3;
            temp03 = cipher2 ^ temp02;
            temp04 = cipher1 ^ temp02;
            temp05 = cipher0 ^ cipher3;
            temp06 = temp04 & temp03;
            temp07 = cipher1 & temp01;
            alt2 = temp05 ^ temp06;
            temp09 = cipher0 ^ temp03;
            alt0 = temp07 ^ temp03;
            temp11 = alt0 | temp05;
            temp12 = temp09 & temp11;
            temp13 = cipher0 & alt2;
            temp14 = temp01 ^ temp05;
            alt1 = cipher1 ^ temp12;
            temp16 = cipher1 | temp13;
            alt3 = temp14 ^ temp16;

            alt0 ^= _expandedKey[19][0];
            alt1 ^= _expandedKey[19][1];
            alt2 ^= _expandedKey[19][2];
            alt3 ^= _expandedKey[19][3];
            cipher2 = ((((alt2)) << (32 - (22))) | (((alt2)) >> (22)));
            cipher0 = ((((alt0)) << (32 - (5))) | (((alt0)) >> (5)));
            cipher2 = cipher2 ^ alt3 ^ (alt1 << 7);
            cipher0 = cipher0 ^ alt1 ^ alt3;
            cipher3 = ((((alt3)) << (32 - (7))) | (((alt3)) >> (7)));
            cipher1 = ((((alt1)) << (32 - (1))) | (((alt1)) >> (1)));
            cipher3 = cipher3 ^ cipher2 ^ (cipher0) << 3;
            cipher1 = cipher1 ^ cipher0 ^ cipher2;
            cipher2 = ((((cipher2)) << (32 - (3))) | (((cipher2)) >> (3)));
            cipher0 = ((((cipher0)) << (32 - (13))) | (((cipher0)) >> (13)));

            temp01 = cipher0 ^ cipher3;
            temp02 = cipher2 ^ cipher3;
            temp03 = cipher0 & cipher2;
            temp04 = cipher1 | temp02;
            alt0 = temp01 ^ temp04;
            temp06 = cipher0 | cipher2;
            temp07 = cipher3 | alt0;
            temp08 = ~ cipher3;
            temp09 = cipher1 & temp06;
            temp10 = temp08 | temp03;
            temp11 = cipher1 & temp07;
            temp12 = temp06 & temp02;
            alt3 = temp09 ^ temp10;
            alt1 = temp12 ^ temp11;
            temp15 = cipher2 & alt3;
            temp16 = alt0 ^ alt1;
            temp17 = temp10 ^ temp15;
            alt2 = temp16 ^ temp17;

            alt0 ^= _expandedKey[18][0];
            alt1 ^= _expandedKey[18][1];
            alt2 ^= _expandedKey[18][2];
            alt3 ^= _expandedKey[18][3];
            cipher2 = ((((alt2)) << (32 - (22))) | (((alt2)) >> (22)));
            cipher0 = ((((alt0)) << (32 - (5))) | (((alt0)) >> (5)));
            cipher2 = cipher2 ^ alt3 ^ (alt1 << 7);
            cipher0 = cipher0 ^ alt1 ^ alt3;
            cipher3 = ((((alt3)) << (32 - (7))) | (((alt3)) >> (7)));
            cipher1 = ((((alt1)) << (32 - (1))) | (((alt1)) >> (1)));
            cipher3 = cipher3 ^ cipher2 ^ (cipher0) << 3;
            cipher1 = cipher1 ^ cipher0 ^ cipher2;
            cipher2 = ((((cipher2)) << (32 - (3))) | (((cipher2)) >> (3)));
            cipher0 = ((((cipher0)) << (32 - (13))) | (((cipher0)) >> (13)));

            temp01 = cipher0 ^ cipher1;
            temp02 = cipher1 | cipher3;
            temp03 = cipher0 & cipher2;
            temp04 = cipher2 ^ temp02;
            temp05 = cipher0 | temp04;
            temp06 = temp01 & temp05;
            temp07 = cipher3 | temp03;
            temp08 = cipher1 ^ temp06;
            temp09 = temp07 ^ temp06;
            temp10 = temp04 | temp03;
            temp11 = cipher3 & temp08;
            alt2 = ~ temp09;
            alt1 = temp10 ^ temp11;
            temp14 = cipher0 | alt2;
            temp15 = temp06 ^ alt1;
            alt3 = temp01 ^ temp04;
            temp17 = cipher2 ^ temp15;
            alt0 = temp14 ^ temp17;

            alt0 ^= _expandedKey[17][0];
            alt1 ^= _expandedKey[17][1];
            alt2 ^= _expandedKey[17][2];
            alt3 ^= _expandedKey[17][3];
            cipher2 = ((((alt2)) << (32 - (22))) | (((alt2)) >> (22)));
            cipher0 = ((((alt0)) << (32 - (5))) | (((alt0)) >> (5)));
            cipher2 = cipher2 ^ alt3 ^ (alt1 << 7);
            cipher0 = cipher0 ^ alt1 ^ alt3;
            cipher3 = ((((alt3)) << (32 - (7))) | (((alt3)) >> (7)));
            cipher1 = ((((alt1)) << (32 - (1))) | (((alt1)) >> (1)));
            cipher3 = cipher3 ^ cipher2 ^ (cipher0) << 3;
            cipher1 = cipher1 ^ cipher0 ^ cipher2;
            cipher2 = ((((cipher2)) << (32 - (3))) | (((cipher2)) >> (3)));
            cipher0 = ((((cipher0)) << (32 - (13))) | (((cipher0)) >> (13)));

            temp01 = cipher2 ^ cipher3;
            temp02 = cipher0 | cipher1;
            temp03 = cipher1 | cipher2;
            temp04 = cipher2 & temp01;
            temp05 = temp02 ^ temp01;
            temp06 = cipher0 | temp04;
            alt2 = ~ temp05;
            temp08 = cipher1 ^ cipher3;
            temp09 = temp03 & temp08;
            temp10 = cipher3 | alt2;
            alt1 = temp09 ^ temp06;
            temp12 = cipher0 | temp05;
            temp13 = alt1 ^ temp12;
            temp14 = temp03 ^ temp10;
            temp15 = cipher0 ^ cipher2;
            alt3 = temp14 ^ temp13;
            temp17 = temp05 & temp13;
            temp18 = temp14 | temp17;
            alt0 = temp15 ^ temp18;

            alt0 ^= _expandedKey[16][0];
            alt1 ^= _expandedKey[16][1];
            alt2 ^= _expandedKey[16][2];
            alt3 ^= _expandedKey[16][3];
            cipher2 = ((((alt2)) << (32 - (22))) | (((alt2)) >> (22)));
            cipher0 = ((((alt0)) << (32 - (5))) | (((alt0)) >> (5)));
            cipher2 = cipher2 ^ alt3 ^ (alt1 << 7);
            cipher0 = cipher0 ^ alt1 ^ alt3;
            cipher3 = ((((alt3)) << (32 - (7))) | (((alt3)) >> (7)));
            cipher1 = ((((alt1)) << (32 - (1))) | (((alt1)) >> (1)));
            cipher3 = cipher3 ^ cipher2 ^ (cipher0) << 3;
            cipher1 = cipher1 ^ cipher0 ^ cipher2;
            cipher2 = ((((cipher2)) << (32 - (3))) | (((cipher2)) >> (3)));
            cipher0 = ((((cipher0)) << (32 - (13))) | (((cipher0)) >> (13)));

            temp01 = cipher0 & cipher1;
            temp02 = cipher0 | cipher1;
            temp03 = cipher2 | temp01;
            temp04 = cipher3 & temp02;
            alt3 = temp03 ^ temp04;
            temp06 = cipher1 ^ temp04;
            temp07 = cipher3 ^ alt3;
            temp08 = ~ temp07;
            temp09 = temp06 | temp08;
            temp10 = cipher1 ^ cipher3;
            temp11 = cipher0 | cipher3;
            alt1 = cipher0 ^ temp09;
            temp13 = cipher2 ^ temp06;
            temp14 = cipher2 & temp11;
            temp15 = cipher3 | alt1;
            temp16 = temp01 | temp10;
            alt0 = temp13 ^ temp15;
            alt2 = temp14 ^ temp16;

            alt0 ^= _expandedKey[15][0];
            alt1 ^= _expandedKey[15][1];
            alt2 ^= _expandedKey[15][2];
            alt3 ^= _expandedKey[15][3];
            cipher2 = ((((alt2)) << (32 - (22))) | (((alt2)) >> (22)));
            cipher0 = ((((alt0)) << (32 - (5))) | (((alt0)) >> (5)));
            cipher2 = cipher2 ^ alt3 ^ (alt1 << 7);
            cipher0 = cipher0 ^ alt1 ^ alt3;
            cipher3 = ((((alt3)) << (32 - (7))) | (((alt3)) >> (7)));
            cipher1 = ((((alt1)) << (32 - (1))) | (((alt1)) >> (1)));
            cipher3 = cipher3 ^ cipher2 ^ (cipher0) << 3;
            cipher1 = cipher1 ^ cipher0 ^ cipher2;
            cipher2 = ((((cipher2)) << (32 - (3))) | (((cipher2)) >> (3)));
            cipher0 = ((((cipher0)) << (32 - (13))) | (((cipher0)) >> (13)));

            temp01 = cipher0 ^ cipher2;
            temp02 = ~ cipher2;
            temp03 = cipher1 & temp01;
            temp04 = cipher1 | temp02;
            temp05 = cipher3 | temp03;
            temp06 = cipher1 ^ cipher3;
            temp07 = cipher0 & temp04;
            temp08 = cipher0 | temp02;
            temp09 = temp07 ^ temp05;
            alt1 = temp06 ^ temp08;
            alt0 = ~ temp09;
            temp12 = cipher1 & alt0;
            temp13 = temp01 & temp05;
            temp14 = temp01 ^ temp12;
            temp15 = temp07 ^ temp13;
            temp16 = cipher3 | temp02;
            temp17 = cipher0 ^ alt1;
            alt3 = temp17 ^ temp15;
            alt2 = temp16 ^ temp14;

            alt0 ^= _expandedKey[14][0];
            alt1 ^= _expandedKey[14][1];
            alt2 ^= _expandedKey[14][2];
            alt3 ^= _expandedKey[14][3];
            cipher2 = ((((alt2)) << (32 - (22))) | (((alt2)) >> (22)));
            cipher0 = ((((alt0)) << (32 - (5))) | (((alt0)) >> (5)));
            cipher2 = cipher2 ^ alt3 ^ (alt1 << 7);
            cipher0 = cipher0 ^ alt1 ^ alt3;
            cipher3 = ((((alt3)) << (32 - (7))) | (((alt3)) >> (7)));
            cipher1 = ((((alt1)) << (32 - (1))) | (((alt1)) >> (1)));
            cipher3 = cipher3 ^ cipher2 ^ (cipher0) << 3;
            cipher1 = cipher1 ^ cipher0 ^ cipher2;
            cipher2 = ((((cipher2)) << (32 - (3))) | (((cipher2)) >> (3)));
            cipher0 = ((((cipher0)) << (32 - (13))) | (((cipher0)) >> (13)));

            temp01 = cipher0 & cipher3;
            temp02 = cipher2 ^ temp01;
            temp03 = cipher0 ^ cipher3;
            temp04 = cipher1 & temp02;
            temp05 = cipher0 & cipher2;
            alt0 = temp03 ^ temp04;
            temp07 = cipher0 & alt0;
            temp08 = temp01 ^ alt0;
            temp09 = cipher1 | temp05;
            temp10 = ~ cipher1;
            alt1 = temp08 ^ temp09;
            temp12 = temp10 | temp07;
            temp13 = alt0 | alt1;
            alt3 = temp02 ^ temp12;
            temp15 = temp02 ^ temp13;
            temp16 = cipher1 ^ cipher3;
            alt2 = temp16 ^ temp15;

            alt0 ^= _expandedKey[13][0];
            alt1 ^= _expandedKey[13][1];
            alt2 ^= _expandedKey[13][2];
            alt3 ^= _expandedKey[13][3];
            cipher2 = ((((alt2)) << (32 - (22))) | (((alt2)) >> (22)));
            cipher0 = ((((alt0)) << (32 - (5))) | (((alt0)) >> (5)));
            cipher2 = cipher2 ^ alt3 ^ (alt1 << 7);
            cipher0 = cipher0 ^ alt1 ^ alt3;
            cipher3 = ((((alt3)) << (32 - (7))) | (((alt3)) >> (7)));
            cipher1 = ((((alt1)) << (32 - (1))) | (((alt1)) >> (1)));
            cipher3 = cipher3 ^ cipher2 ^ (cipher0) << 3;
            cipher1 = cipher1 ^ cipher0 ^ cipher2;
            cipher2 = ((((cipher2)) << (32 - (3))) | (((cipher2)) >> (3)));
            cipher0 = ((((cipher0)) << (32 - (13))) | (((cipher0)) >> (13)));

            temp01 = cipher1 | cipher3;
            temp02 = cipher2 | cipher3;
            temp03 = cipher0 & temp01;
            temp04 = cipher1 ^ temp02;
            temp05 = cipher2 ^ cipher3;
            temp06 = ~ temp03;
            temp07 = cipher0 & temp04;
            alt1 = temp05 ^ temp07;
            temp09 = alt1 | temp06;
            temp10 = cipher0 ^ temp07;
            temp11 = temp01 ^ temp09;
            temp12 = cipher3 ^ temp04;
            temp13 = cipher2 | temp10;
            alt3 = temp03 ^ temp12;
            temp15 = cipher0 ^ temp04;
            alt2 = temp11 ^ temp13;
            alt0 = temp15 ^ temp09;

            alt0 ^= _expandedKey[12][0];
            alt1 ^= _expandedKey[12][1];
            alt2 ^= _expandedKey[12][2];
            alt3 ^= _expandedKey[12][3];
            cipher2 = ((((alt2)) << (32 - (22))) | (((alt2)) >> (22)));
            cipher0 = ((((alt0)) << (32 - (5))) | (((alt0)) >> (5)));
            cipher2 = cipher2 ^ alt3 ^ (alt1 << 7);
            cipher0 = cipher0 ^ alt1 ^ alt3;
            cipher3 = ((((alt3)) << (32 - (7))) | (((alt3)) >> (7)));
            cipher1 = ((((alt1)) << (32 - (1))) | (((alt1)) >> (1)));
            cipher3 = cipher3 ^ cipher2 ^ (cipher0) << 3;
            cipher1 = cipher1 ^ cipher0 ^ cipher2;
            cipher2 = ((((cipher2)) << (32 - (3))) | (((cipher2)) >> (3)));
            cipher0 = ((((cipher0)) << (32 - (13))) | (((cipher0)) >> (13)));

            temp01 = cipher2 | cipher3;
            temp02 = cipher0 | cipher3;
            temp03 = cipher2 ^ temp02;
            temp04 = cipher1 ^ temp02;
            temp05 = cipher0 ^ cipher3;
            temp06 = temp04 & temp03;
            temp07 = cipher1 & temp01;
            alt2 = temp05 ^ temp06;
            temp09 = cipher0 ^ temp03;
            alt0 = temp07 ^ temp03;
            temp11 = alt0 | temp05;
            temp12 = temp09 & temp11;
            temp13 = cipher0 & alt2;
            temp14 = temp01 ^ temp05;
            alt1 = cipher1 ^ temp12;
            temp16 = cipher1 | temp13;
            alt3 = temp14 ^ temp16;

            alt0 ^= _expandedKey[11][0];
            alt1 ^= _expandedKey[11][1];
            alt2 ^= _expandedKey[11][2];
            alt3 ^= _expandedKey[11][3];
            cipher2 = ((((alt2)) << (32 - (22))) | (((alt2)) >> (22)));
            cipher0 = ((((alt0)) << (32 - (5))) | (((alt0)) >> (5)));
            cipher2 = cipher2 ^ alt3 ^ (alt1 << 7);
            cipher0 = cipher0 ^ alt1 ^ alt3;
            cipher3 = ((((alt3)) << (32 - (7))) | (((alt3)) >> (7)));
            cipher1 = ((((alt1)) << (32 - (1))) | (((alt1)) >> (1)));
            cipher3 = cipher3 ^ cipher2 ^ (cipher0) << 3;
            cipher1 = cipher1 ^ cipher0 ^ cipher2;
            cipher2 = ((((cipher2)) << (32 - (3))) | (((cipher2)) >> (3)));
            cipher0 = ((((cipher0)) << (32 - (13))) | (((cipher0)) >> (13)));

            temp01 = cipher0 ^ cipher3;
            temp02 = cipher2 ^ cipher3;
            temp03 = cipher0 & cipher2;
            temp04 = cipher1 | temp02;
            alt0 = temp01 ^ temp04;
            temp06 = cipher0 | cipher2;
            temp07 = cipher3 | alt0;
            temp08 = ~ cipher3;
            temp09 = cipher1 & temp06;
            temp10 = temp08 | temp03;
            temp11 = cipher1 & temp07;
            temp12 = temp06 & temp02;
            alt3 = temp09 ^ temp10;
            alt1 = temp12 ^ temp11;
            temp15 = cipher2 & alt3;
            temp16 = alt0 ^ alt1;
            temp17 = temp10 ^ temp15;
            alt2 = temp16 ^ temp17;

            alt0 ^= _expandedKey[10][0];
            alt1 ^= _expandedKey[10][1];
            alt2 ^= _expandedKey[10][2];
            alt3 ^= _expandedKey[10][3];
            cipher2 = ((((alt2)) << (32 - (22))) | (((alt2)) >> (22)));
            cipher0 = ((((alt0)) << (32 - (5))) | (((alt0)) >> (5)));
            cipher2 = cipher2 ^ alt3 ^ (alt1 << 7);
            cipher0 = cipher0 ^ alt1 ^ alt3;
            cipher3 = ((((alt3)) << (32 - (7))) | (((alt3)) >> (7)));
            cipher1 = ((((alt1)) << (32 - (1))) | (((alt1)) >> (1)));
            cipher3 = cipher3 ^ cipher2 ^ (cipher0) << 3;
            cipher1 = cipher1 ^ cipher0 ^ cipher2;
            cipher2 = ((((cipher2)) << (32 - (3))) | (((cipher2)) >> (3)));
            cipher0 = ((((cipher0)) << (32 - (13))) | (((cipher0)) >> (13)));

            temp01 = cipher0 ^ cipher1;
            temp02 = cipher1 | cipher3;
            temp03 = cipher0 & cipher2;
            temp04 = cipher2 ^ temp02;
            temp05 = cipher0 | temp04;
            temp06 = temp01 & temp05;
            temp07 = cipher3 | temp03;
            temp08 = cipher1 ^ temp06;
            temp09 = temp07 ^ temp06;
            temp10 = temp04 | temp03;
            temp11 = cipher3 & temp08;
            alt2 = ~ temp09;
            alt1 = temp10 ^ temp11;
            temp14 = cipher0 | alt2;
            temp15 = temp06 ^ alt1;
            alt3 = temp01 ^ temp04;
            temp17 = cipher2 ^ temp15;
            alt0 = temp14 ^ temp17;

            alt0 ^= _expandedKey[9][0];
            alt1 ^= _expandedKey[9][1];
            alt2 ^= _expandedKey[9][2];
            alt3 ^= _expandedKey[9][3];
            cipher2 = ((((alt2)) << (32 - (22))) | (((alt2)) >> (22)));
            cipher0 = ((((alt0)) << (32 - (5))) | (((alt0)) >> (5)));
            cipher2 = cipher2 ^ alt3 ^ (alt1 << 7);
            cipher0 = cipher0 ^ alt1 ^ alt3;
            cipher3 = ((((alt3)) << (32 - (7))) | (((alt3)) >> (7)));
            cipher1 = ((((alt1)) << (32 - (1))) | (((alt1)) >> (1)));
            cipher3 = cipher3 ^ cipher2 ^ (cipher0) << 3;
            cipher1 = cipher1 ^ cipher0 ^ cipher2;
            cipher2 = ((((cipher2)) << (32 - (3))) | (((cipher2)) >> (3)));
            cipher0 = ((((cipher0)) << (32 - (13))) | (((cipher0)) >> (13)));

            temp01 = cipher2 ^ cipher3;
            temp02 = cipher0 | cipher1;
            temp03 = cipher1 | cipher2;
            temp04 = cipher2 & temp01;
            temp05 = temp02 ^ temp01;
            temp06 = cipher0 | temp04;
            alt2 = ~ temp05;
            temp08 = cipher1 ^ cipher3;
            temp09 = temp03 & temp08;
            temp10 = cipher3 | alt2;
            alt1 = temp09 ^ temp06;
            temp12 = cipher0 | temp05;
            temp13 = alt1 ^ temp12;
            temp14 = temp03 ^ temp10;
            temp15 = cipher0 ^ cipher2;
            alt3 = temp14 ^ temp13;
            temp17 = temp05 & temp13;
            temp18 = temp14 | temp17;
            alt0 = temp15 ^ temp18;

            alt0 ^= _expandedKey[8][0];
            alt1 ^= _expandedKey[8][1];
            alt2 ^= _expandedKey[8][2];
            alt3 ^= _expandedKey[8][3];
            cipher2 = ((((alt2)) << (32 - (22))) | (((alt2)) >> (22)));
            cipher0 = ((((alt0)) << (32 - (5))) | (((alt0)) >> (5)));
            cipher2 = cipher2 ^ alt3 ^ (alt1 << 7);
            cipher0 = cipher0 ^ alt1 ^ alt3;
            cipher3 = ((((alt3)) << (32 - (7))) | (((alt3)) >> (7)));
            cipher1 = ((((alt1)) << (32 - (1))) | (((alt1)) >> (1)));
            cipher3 = cipher3 ^ cipher2 ^ (cipher0) << 3;
            cipher1 = cipher1 ^ cipher0 ^ cipher2;
            cipher2 = ((((cipher2)) << (32 - (3))) | (((cipher2)) >> (3)));
            cipher0 = ((((cipher0)) << (32 - (13))) | (((cipher0)) >> (13)));

            temp01 = cipher0 & cipher1;
            temp02 = cipher0 | cipher1;
            temp03 = cipher2 | temp01;
            temp04 = cipher3 & temp02;
            alt3 = temp03 ^ temp04;
            temp06 = cipher1 ^ temp04;
            temp07 = cipher3 ^ alt3;
            temp08 = ~ temp07;
            temp09 = temp06 | temp08;
            temp10 = cipher1 ^ cipher3;
            temp11 = cipher0 | cipher3;
            alt1 = cipher0 ^ temp09;
            temp13 = cipher2 ^ temp06;
            temp14 = cipher2 & temp11;
            temp15 = cipher3 | alt1;
            temp16 = temp01 | temp10;
            alt0 = temp13 ^ temp15;
            alt2 = temp14 ^ temp16;

            alt0 ^= _expandedKey[7][0];
            alt1 ^= _expandedKey[7][1];
            alt2 ^= _expandedKey[7][2];
            alt3 ^= _expandedKey[7][3];
            cipher2 = ((((alt2)) << (32 - (22))) | (((alt2)) >> (22)));
            cipher0 = ((((alt0)) << (32 - (5))) | (((alt0)) >> (5)));
            cipher2 = cipher2 ^ alt3 ^ (alt1 << 7);
            cipher0 = cipher0 ^ alt1 ^ alt3;
            cipher3 = ((((alt3)) << (32 - (7))) | (((alt3)) >> (7)));
            cipher1 = ((((alt1)) << (32 - (1))) | (((alt1)) >> (1)));
            cipher3 = cipher3 ^ cipher2 ^ (cipher0) << 3;
            cipher1 = cipher1 ^ cipher0 ^ cipher2;
            cipher2 = ((((cipher2)) << (32 - (3))) | (((cipher2)) >> (3)));
            cipher0 = ((((cipher0)) << (32 - (13))) | (((cipher0)) >> (13)));

            temp01 = cipher0 ^ cipher2;
            temp02 = ~ cipher2;
            temp03 = cipher1 & temp01;
            temp04 = cipher1 | temp02;
            temp05 = cipher3 | temp03;
            temp06 = cipher1 ^ cipher3;
            temp07 = cipher0 & temp04;
            temp08 = cipher0 | temp02;
            temp09 = temp07 ^ temp05;
            alt1 = temp06 ^ temp08;
            alt0 = ~ temp09;
            temp12 = cipher1 & alt0;
            temp13 = temp01 & temp05;
            temp14 = temp01 ^ temp12;
            temp15 = temp07 ^ temp13;
            temp16 = cipher3 | temp02;
            temp17 = cipher0 ^ alt1;
            alt3 = temp17 ^ temp15;
            alt2 = temp16 ^ temp14;

            alt0 ^= _expandedKey[6][0];
            alt1 ^= _expandedKey[6][1];
            alt2 ^= _expandedKey[6][2];
            alt3 ^= _expandedKey[6][3];
            cipher2 = ((((alt2)) << (32 - (22))) | (((alt2)) >> (22)));
            cipher0 = ((((alt0)) << (32 - (5))) | (((alt0)) >> (5)));
            cipher2 = cipher2 ^ alt3 ^ (alt1 << 7);
            cipher0 = cipher0 ^ alt1 ^ alt3;
            cipher3 = ((((alt3)) << (32 - (7))) | (((alt3)) >> (7)));
            cipher1 = ((((alt1)) << (32 - (1))) | (((alt1)) >> (1)));
            cipher3 = cipher3 ^ cipher2 ^ (cipher0) << 3;
            cipher1 = cipher1 ^ cipher0 ^ cipher2;
            cipher2 = ((((cipher2)) << (32 - (3))) | (((cipher2)) >> (3)));
            cipher0 = ((((cipher0)) << (32 - (13))) | (((cipher0)) >> (13)));

            temp01 = cipher0 & cipher3;
            temp02 = cipher2 ^ temp01;
            temp03 = cipher0 ^ cipher3;
            temp04 = cipher1 & temp02;
            temp05 = cipher0 & cipher2;
            alt0 = temp03 ^ temp04;
            temp07 = cipher0 & alt0;
            temp08 = temp01 ^ alt0;
            temp09 = cipher1 | temp05;
            temp10 = ~ cipher1;
            alt1 = temp08 ^ temp09;
            temp12 = temp10 | temp07;
            temp13 = alt0 | alt1;
            alt3 = temp02 ^ temp12;
            temp15 = temp02 ^ temp13;
            temp16 = cipher1 ^ cipher3;
            alt2 = temp16 ^ temp15;

            alt0 ^= _expandedKey[5][0];
            alt1 ^= _expandedKey[5][1];
            alt2 ^= _expandedKey[5][2];
            alt3 ^= _expandedKey[5][3];
            cipher2 = ((((alt2)) << (32 - (22))) | (((alt2)) >> (22)));
            cipher0 = ((((alt0)) << (32 - (5))) | (((alt0)) >> (5)));
            cipher2 = cipher2 ^ alt3 ^ (alt1 << 7);
            cipher0 = cipher0 ^ alt1 ^ alt3;
            cipher3 = ((((alt3)) << (32 - (7))) | (((alt3)) >> (7)));
            cipher1 = ((((alt1)) << (32 - (1))) | (((alt1)) >> (1)));
            cipher3 = cipher3 ^ cipher2 ^ (cipher0) << 3;
            cipher1 = cipher1 ^ cipher0 ^ cipher2;
            cipher2 = ((((cipher2)) << (32 - (3))) | (((cipher2)) >> (3)));
            cipher0 = ((((cipher0)) << (32 - (13))) | (((cipher0)) >> (13)));

            temp01 = cipher1 | cipher3;
            temp02 = cipher2 | cipher3;
            temp03 = cipher0 & temp01;
            temp04 = cipher1 ^ temp02;
            temp05 = cipher2 ^ cipher3;
            temp06 = ~ temp03;
            temp07 = cipher0 & temp04;
            alt1 = temp05 ^ temp07;
            temp09 = alt1 | temp06;
            temp10 = cipher0 ^ temp07;
            temp11 = temp01 ^ temp09;
            temp12 = cipher3 ^ temp04;
            temp13 = cipher2 | temp10;
            alt3 = temp03 ^ temp12;
            temp15 = cipher0 ^ temp04;
            alt2 = temp11 ^ temp13;
            alt0 = temp15 ^ temp09;

            alt0 ^= _expandedKey[4][0];
            alt1 ^= _expandedKey[4][1];
            alt2 ^= _expandedKey[4][2];
            alt3 ^= _expandedKey[4][3];
            cipher2 = ((((alt2)) << (32 - (22))) | (((alt2)) >> (22)));
            cipher0 = ((((alt0)) << (32 - (5))) | (((alt0)) >> (5)));
            cipher2 = cipher2 ^ alt3 ^ (alt1 << 7);
            cipher0 = cipher0 ^ alt1 ^ alt3;
            cipher3 = ((((alt3)) << (32 - (7))) | (((alt3)) >> (7)));
            cipher1 = ((((alt1)) << (32 - (1))) | (((alt1)) >> (1)));
            cipher3 = cipher3 ^ cipher2 ^ (cipher0) << 3;
            cipher1 = cipher1 ^ cipher0 ^ cipher2;
            cipher2 = ((((cipher2)) << (32 - (3))) | (((cipher2)) >> (3)));
            cipher0 = ((((cipher0)) << (32 - (13))) | (((cipher0)) >> (13)));

            temp01 = cipher2 | cipher3;
            temp02 = cipher0 | cipher3;
            temp03 = cipher2 ^ temp02;
            temp04 = cipher1 ^ temp02;
            temp05 = cipher0 ^ cipher3;
            temp06 = temp04 & temp03;
            temp07 = cipher1 & temp01;
            alt2 = temp05 ^ temp06;
            temp09 = cipher0 ^ temp03;
            alt0 = temp07 ^ temp03;
            temp11 = alt0 | temp05;
            temp12 = temp09 & temp11;
            temp13 = cipher0 & alt2;
            temp14 = temp01 ^ temp05;
            alt1 = cipher1 ^ temp12;
            temp16 = cipher1 | temp13;
            alt3 = temp14 ^ temp16;

            alt0 ^= _expandedKey[3][0];
            alt1 ^= _expandedKey[3][1];
            alt2 ^= _expandedKey[3][2];
            alt3 ^= _expandedKey[3][3];
            cipher2 = ((((alt2)) << (32 - (22))) | (((alt2)) >> (22)));
            cipher0 = ((((alt0)) << (32 - (5))) | (((alt0)) >> (5)));
            cipher2 = cipher2 ^ alt3 ^ (alt1 << 7);
            cipher0 = cipher0 ^ alt1 ^ alt3;
            cipher3 = ((((alt3)) << (32 - (7))) | (((alt3)) >> (7)));
            cipher1 = ((((alt1)) << (32 - (1))) | (((alt1)) >> (1)));
            cipher3 = cipher3 ^ cipher2 ^ (cipher0) << 3;
            cipher1 = cipher1 ^ cipher0 ^ cipher2;
            cipher2 = ((((cipher2)) << (32 - (3))) | (((cipher2)) >> (3)));
            cipher0 = ((((cipher0)) << (32 - (13))) | (((cipher0)) >> (13)));

            temp01 = cipher0 ^ cipher3;
            temp02 = cipher2 ^ cipher3;
            temp03 = cipher0 & cipher2;
            temp04 = cipher1 | temp02;
            alt0 = temp01 ^ temp04;
            temp06 = cipher0 | cipher2;
            temp07 = cipher3 | alt0;
            temp08 = ~ cipher3;
            temp09 = cipher1 & temp06;
            temp10 = temp08 | temp03;
            temp11 = cipher1 & temp07;
            temp12 = temp06 & temp02;
            alt3 = temp09 ^ temp10;
            alt1 = temp12 ^ temp11;
            temp15 = cipher2 & alt3;
            temp16 = alt0 ^ alt1;
            temp17 = temp10 ^ temp15;
            alt2 = temp16 ^ temp17;

            alt0 ^= _expandedKey[2][0];
            alt1 ^= _expandedKey[2][1];
            alt2 ^= _expandedKey[2][2];
            alt3 ^= _expandedKey[2][3];
            cipher2 = ((((alt2)) << (32 - (22))) | (((alt2)) >> (22)));
            cipher0 = ((((alt0)) << (32 - (5))) | (((alt0)) >> (5)));
            cipher2 = cipher2 ^ alt3 ^ (alt1 << 7);
            cipher0 = cipher0 ^ alt1 ^ alt3;
            cipher3 = ((((alt3)) << (32 - (7))) | (((alt3)) >> (7)));
            cipher1 = ((((alt1)) << (32 - (1))) | (((alt1)) >> (1)));
            cipher3 = cipher3 ^ cipher2 ^ (cipher0) << 3;
            cipher1 = cipher1 ^ cipher0 ^ cipher2;
            cipher2 = ((((cipher2)) << (32 - (3))) | (((cipher2)) >> (3)));
            cipher0 = ((((cipher0)) << (32 - (13))) | (((cipher0)) >> (13)));

            temp01 = cipher0 ^ cipher1;
            temp02 = cipher1 | cipher3;
            temp03 = cipher0 & cipher2;
            temp04 = cipher2 ^ temp02;
            temp05 = cipher0 | temp04;
            temp06 = temp01 & temp05;
            temp07 = cipher3 | temp03;
            temp08 = cipher1 ^ temp06;
            temp09 = temp07 ^ temp06;
            temp10 = temp04 | temp03;
            temp11 = cipher3 & temp08;
            alt2 = ~ temp09;
            alt1 = temp10 ^ temp11;
            temp14 = cipher0 | alt2;
            temp15 = temp06 ^ alt1;
            alt3 = temp01 ^ temp04;
            temp17 = cipher2 ^ temp15;
            alt0 = temp14 ^ temp17;

            alt0 ^= _expandedKey[1][0];
            alt1 ^= _expandedKey[1][1];
            alt2 ^= _expandedKey[1][2];
            alt3 ^= _expandedKey[1][3];
            cipher2 = ((((alt2)) << (32 - (22))) | (((alt2)) >> (22)));
            cipher0 = ((((alt0)) << (32 - (5))) | (((alt0)) >> (5)));
            cipher2 = cipher2 ^ alt3 ^ (alt1 << 7);
            cipher0 = cipher0 ^ alt1 ^ alt3;
            cipher3 = ((((alt3)) << (32 - (7))) | (((alt3)) >> (7)));
            cipher1 = ((((alt1)) << (32 - (1))) | (((alt1)) >> (1)));
            cipher3 = cipher3 ^ cipher2 ^ (cipher0) << 3;
            cipher1 = cipher1 ^ cipher0 ^ cipher2;
            cipher2 = ((((cipher2)) << (32 - (3))) | (((cipher2)) >> (3)));
            cipher0 = ((((cipher0)) << (32 - (13))) | (((cipher0)) >> (13)));

            temp01 = cipher2 ^ cipher3;
            temp02 = cipher0 | cipher1;
            temp03 = cipher1 | cipher2;
            temp04 = cipher2 & temp01;
            temp05 = temp02 ^ temp01;
            temp06 = cipher0 | temp04;
            alt2 = ~ temp05;
            temp08 = cipher1 ^ cipher3;
            temp09 = temp03 & temp08;
            temp10 = cipher3 | alt2;
            alt1 = temp09 ^ temp06;
            temp12 = cipher0 | temp05;
            temp13 = alt1 ^ temp12;
            temp14 = temp03 ^ temp10;
            temp15 = cipher0 ^ cipher2;
            alt3 = temp14 ^ temp13;
            temp17 = temp05 & temp13;
            temp18 = temp14 | temp17;
            alt0 = temp15 ^ temp18;

            cipher[0] = alt0 ^ _expandedKey[0][0];
            cipher[1] = alt1 ^ _expandedKey[0][1];
            cipher[2] = alt2 ^ _expandedKey[0][2];
            cipher[3] = alt3 ^ _expandedKey[0][3];
        }

        /// <summary>
        /// Encrypts a single block of bytes, writing the result into the
        /// provided array.
        /// </summary>
        /// <param name="block">
        /// The block of bytes to be encrypted.
        /// </param>
        protected override void EncryptBlock(byte[] block)
        {
            uint[] words = Utils.BytesToWordsLittleEndian(block);
            Encrypt(words);
            Utils.WriteWordsIntoBytesLittleEndian(words, block);
        }

        /// <summary>
        /// Decrypts a single block of bytes, writing the result into the
        /// provided array.
        /// </summary>
        /// <param name="block">
        /// The block of bytes to be decrypted.
        /// </param>
        protected override void DecryptBlock(byte[] block)
        {
            uint[] words = Utils.BytesToWordsLittleEndian(block);
            Decrypt(words);
            Utils.WriteWordsIntoBytesLittleEndian(words, block);
        }

        /// <summary>
        /// Clears all potentially sensitive data stores.
        /// </summary>
        protected internal override void Reset()
        {
            if (_key != null)
            {
                Array.Clear(_key, 0, _key.Length);
                _key = null;
            }
            if (_expandedKey != null)
            {
                foreach (var subArray in _expandedKey)
                {
                    if (subArray != null)
                    {
                        Array.Clear(subArray, 0, subArray.Length);
                    }
                }
                _expandedKey = null;
            }
            base.Reset();
        }
    }
}
