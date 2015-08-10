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
    /// Interface defining properties that must be exposed by symmetric
    /// algorithm implementations in this library.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Some of these are exposed already by the
    /// <see cref="SymmetricAlgorithm" /> base class in the .NET framework,
    /// but this implementation additionally defines properties that are
    /// required to support the following enhancements:
    /// </para>
    /// <list type="bullet">
    /// <item>
    /// Counter (<see cref="ExtendedCipherMode.CTR" />) block cipher mode,
    /// with one of thre methods for combining the counter and nonce values.
    /// </item>
    /// <item>
    /// Variable size cipher feedback (<see cref="ExtendedCipherMode.CFB" />)
    /// mode.
    /// </item>
    /// </list>
    /// </remarks>
    public interface ISymmetricAlgorithm
    {
        /// <summary>
        /// Gets or sets the block size for this instance of the algorithm.
        /// </summary>
        /// <remarks>
        /// Some algorithms allow for a variable block size, which is why this
        /// is exposed as an instance and not a static member.
        /// </remarks>
        /// <value>
        /// The block size for this instance of the algorithm.
        /// </value>
        int BlockSize { get; set; }

        /// <summary>
        /// Gets or sets the padding mode to be used by this instance of the
        /// algorithm.
        /// </summary>
        /// <exception cref="CryptographicException">
        /// The padding mode is not one of the <see cref="PaddingMode"/>
        /// values.
        /// </exception>
        /// <value>
        /// The padding mode to be used by this instance of the algorithm.
        /// </value>
        PaddingMode Padding { get; set; }

        /// <summary>
        /// Gets or sets the block cipher chaining mode to be used by this
        /// instance of the algorithm.
        /// </summary>
        /// <remarks>
        /// If compatible, this property's setter also sets the underlying
        /// <see cref="SymmetricAlgorithm.Mode" /> property, which is of the
        /// more restrictive type <see cref="CipherMode" />. The default mode
        /// is <see cref="ExtendedCipherMode.CBC"/>.
        /// </remarks>
        /// <exception cref="CryptographicException">
        /// The cipher mode is not one of the <see cref="ExtendedCipherMode"/>
        /// values.
        /// </exception>
        /// <value>
        /// The block cipher chaining mode to be used by this instance of the
        /// algorithm.
        /// </value>
        ExtendedCipherMode ExtendedMode { get; set; }

        /// <summary>
        /// Gets or sets the method used to combine the counter value with the
        /// nonce in counter (<see cref="ExtendedCipherMode.CTR" />) mode.
        /// </summary>
        /// <exception cref="CryptographicException">
        /// The mode is not one of the <see cref="NonceCombinationMode"/>
        /// values.
        /// </exception>
        /// <value>
        /// The method used to combine the counter value with the nonce in
        /// counter (<see cref="ExtendedCipherMode.CTR" />) mode.
        /// </value>
        NonceCombinationMode NonceCombinationMode { get; set; }

        /// <summary>
        /// Gets or sets the number of bytes to process at a time in cipher or
        /// output feedback (<see cref="ExtendedCipherMode.CFB" /> or
        /// <see cref="ExtendedCipherMode.OFB" />) modes.
        /// </summary>
        /// <remarks>
        /// If not set, this value will default to 1 byte, which provides
        /// compatibility with the CSP and .NET implementations of the
        /// modes.
        /// </remarks>
        /// <value>
        /// The number of bytes to process at a time in cipher or
        /// output feedback (<see cref="ExtendedCipherMode.CFB" /> or
        /// <see cref="ExtendedCipherMode.OFB" />) modes.
        /// </value>
        int RegisterShiftSize { get; set; }

        /// <summary>
        /// Returns a random non-weak key
        /// (<see cref="P:System.Security.Cryptography.SymmetricAlgorithm.Key"/>)
        /// to use for the algorithm.
        /// </summary>
        /// <returns></returns>
        byte[] GenerateNonWeakKey();
    }
}
