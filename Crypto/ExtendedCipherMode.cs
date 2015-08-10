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

using System.Security.Cryptography;

namespace DotNetCrypt
{
    /// <summary>
    /// Specified the block cipher chaining mode to be used for multiple block
    /// encryption and decryption.</summary>
    /// <remarks>
    /// This mirrors the <see cref="CipherMode"/> enumeration of the .NET
    /// framework's <see cref="System.Security.Cryptography"/> namespace, but
    /// additionally adds CTR (counter) mode.
    /// </remarks>
    public enum ExtendedCipherMode
    {
// ReSharper disable InconsistentNaming
        /// <summary>
        /// The Electronic Codebook (<see cref="ECB" />) mode encrypts each
        /// block individually. This means that any blocks of plain text that
        /// are identical and are in the same message, or in a different
        /// message encrypted with the same key, will be transformed into
        /// identical cipher text blocks. If the plain text to be encrypted
        /// contains substantial repetition, it is feasible for the cipher
        /// text to be broken one block at a time. Also, it is possible for an
        /// active adversary to substitute and exchange individual blocks
        /// without detection. If a single bit of the cipher text block is
        /// mangled, the entire corresponding plain text block will also be
        /// mangled.
        /// </summary>
        ECB = CipherMode.ECB,
        /// <summary>
        /// The Output Feedback (<see cref="OFB" />) mode processes small
        /// increments of plain text into cipher text instead of processing an 
        /// entire block at a time. This mode is similar to <see cref="CFB" />;
        /// the only difference between the two modes is the way that the shift
        /// register is filled. If a bit in the cipher text is mangled, the
        /// corresponding bit of plain text will be mangled. However, if there
        /// are extra or missing bits from the cipher text, the plain text will
        /// be mangled from that point on.
        /// </summary>
        OFB = CipherMode.OFB,
        /// <summary>
        /// The Cipher Feedback (<see cref="CFB" />) mode processes small
        /// increments of plain text into cipher text, instead of processing an
        /// entire block at a time. This mode uses a shift register that is one
        /// block in length and is divided into sections. For example, if the
        /// block size is eight bytes, with one byte processed at a time, the
        /// shift register is divided into eight sections. If a bit in the
        /// cipher text is mangled, one plain text bit is mangled and the shift
        /// register is corrupted. This results in the next several plain text
        /// increments being mangled until the bad bit is shifted out of the
        /// shift register.
        /// </summary>
        CFB = CipherMode.CFB,
        /// <summary>
        /// The Cipher Block Chaining (<see cref="CBC" />) mode introduces
        /// feedback. Before each plain text block is encrypted, it is combined
        /// with the cipher text of the previous block by a bitwise exclusive
        /// OR operation. This ensures that even if the plain text contains
        /// many identical blocks, they will each encrypt to a different cipher
        /// text block. The initialization vector is combined with the first
        /// plain text block by a bitwise exclusive OR operation before the
        /// block is encrypted. If a single bit of the cipher text block is
        /// mangled, the corresponding plain text block will also be mangled.
        /// In addition, a bit in the subsequent block, in the same position as
        /// the original mangled bit, will be mangled.
        /// </summary>
        CBC = CipherMode.CBC,
        /// <summary>
        /// The Cipher Text Stealing (<see cref="CTS" />) mode handles any
        /// length of plain text and produces cipher text whose length matches
        /// the plain text length. This mode behaves like the 
        /// <see cref="CBC" /> mode for all but the last two blocks of the
        /// plain text.
        /// </summary>
        CTS = CipherMode.CTS,
        /// <summary>
        /// The Counter (<see cref="CTR" />) mode generates a stream of output
        /// bits by encrypting a block based on a progressively incrementing
        /// counter variable. This counter can be combined with the algorithm's
        /// initialization vector (IV) is one of a number of ways specified by
        /// the <see cref="NonceCombinationMode" /> enumeration. The output of
        /// this encryption is combined with the plain text blocks by a bitwise
        /// exclusive OR operation ot produce the cipher text. Because there is
        /// no feedback involved, any individual block can be encrypted out of
        /// context, making this mode extremely well suited to parallelized
        /// implementations.
        /// </summary>
        CTR
// ReSharper restore InconsistentNaming
    }
}
