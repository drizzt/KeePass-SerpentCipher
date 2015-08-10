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
using System.Security.Cryptography;
//using DotNetCrypt.Properties;

namespace DotNetCrypt
{
#pragma warning disable 612,618
    /// <summary>
    /// An abstract base class for managed implementations of
    /// <see cref="SymmetricAlgorithm" />.
    /// </summary>
    /// <remarks>
    /// This class introduces the <see cref="ExtendedMode" /> property,
    /// allowing a wider range of block cipher chaining modes to be used. For
    /// this reason, the <see cref="Mode" /> property is now marked with the
    /// <see cref="ObsoleteAttribute" />.
    /// </remarks>
    public abstract class SymmetricAlgorithmBase : SymmetricAlgorithm, ISymmetricAlgorithm
#pragma warning restore 612,618
    {
        /// <summary>
        /// Gets or sets the mode for operation of the symmetric algorithm.
        /// </summary>
        /// <remarks>
        /// Although this property will still work with this library, the use
        /// of the <see cref="ExtendedMode" /> property, which adds support
        /// for <see cref="ExtendedCipherMode.CTR" /> mode, is preferred.
        /// </remarks>
        /// <returns>
        /// The mode for operation of the symmetric algorithm. The default is
        /// <see cref="CipherMode.CBC"/>.
        /// </returns>
        /// <exception cref="CryptographicException">
        /// The cipher mode is not one of the <see cref="CipherMode"/> values.
        /// </exception>
#pragma warning disable 809
        [Obsolete("Use the ExtendedMode property instead.")]
        public override CipherMode Mode
#pragma warning restore 809
        {
            get
            {
                if (ExtendedMode == ExtendedCipherMode.CTR)
                {
					throw new InvalidOperationException (); //Resources.OLD_CIPHER_MODE_CTR);
                }
                return (CipherMode)ExtendedMode;
            }
            set
            {
                ExtendedMode = (ExtendedCipherMode)value;
            }
        }

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
        public ExtendedCipherMode ExtendedMode { get; set; }

        /// <summary>
        /// Gets or sets the method used to combine the counter value with the
        /// nonce in counter (<see cref="ExtendedCipherMode.CTR" />) mode.
        /// </summary>
        /// <exception cref="CryptographicException">
        /// The mode is not one of the <see cref="ISymmetricAlgorithm.NonceCombinationMode"/>
        /// values.
        /// </exception>
        /// <value>
        /// The method used to combine the counter value with the nonce in
        /// counter (<see cref="ExtendedCipherMode.CTR" />) mode.
        /// </value>
        public NonceCombinationMode NonceCombinationMode { get; set; }

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
        public int RegisterShiftSize { get; set; }

        /// <summary>
        /// Gets or sets the secret key for the symmetric algorithm.
        /// </summary>
        /// <returns>
        /// The secret key to use for the symmetric algorithm.
        /// </returns>
        /// <exception cref="T:System.ArgumentNullException">
        /// An attempt was made to set the key to null. 
        /// </exception>
        /// <exception cref="T:System.Security.Cryptography.CryptographicException">
        /// The key size is invalid.
        /// </exception>
        public override byte[] Key
        {
            get
            {
                if (KeyValue == null)
                {
                    GenerateKey();
                }
                // ReSharper disable PossibleNullReferenceException
                return (byte[])(KeyValue.Clone());
                // ReSharper restore PossibleNullReferenceException
            }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException("value");
                }
                if (!ValidKeySize(value.Length << 3))
                {
                    throw new ArgumentException("The specified key size is invalid");
                }
                if (IsWeakKey(value))
                {
                    throw new CryptographicException("The specified key is a weak one", "Blowfish");
                }
                KeyValue = (byte[])value.Clone();
                KeySizeValue = value.Length << 3;
            }
        }

        /// <summary>
        /// Generates a random non-weak key
        /// (<see cref="P:System.Security.Cryptography.SymmetricAlgorithm.Key"/>)
        /// to use for the algorithm.
        /// </summary>
        public override void GenerateKey()
        {
            KeyValue = new byte[KeySizeValue >> 3];
            do
            {
                Utils.RandomNumberGeneratorSingleton.GetBytes(KeyValue);
            } while (IsWeakKey(KeyValue));
        }

        /// <summary>
        /// Returns a random non-weak key
        /// (<see cref="P:System.Security.Cryptography.SymmetricAlgorithm.Key"/>)
        /// to use for the algorithm.
        /// </summary>
        public byte[] GenerateNonWeakKey()
        {
            var key = new byte[KeySizeValue >> 3];
            do
            {
                Utils.RandomNumberGeneratorSingleton.GetBytes(key);
            } while (IsWeakKey(key));
            return key;
        }

        /// <summary>
        /// Generates a random initialization vector
        /// (<see cref="P:System.Security.Cryptography.SymmetricAlgorithm.IV"/>)
        /// to use for the algorithm.
        /// </summary>
        public override void GenerateIV()
        {
            IVValue = new byte[BlockSizeValue / 8];
            Utils.RandomNumberGeneratorSingleton.GetBytes(IVValue);
        }

        /// <summary>
        /// Determines whether the specified key is weak.
        /// </summary>
        /// <param name="rgbKey">
        /// The secret key to test for weakness. 
        /// </param>
        /// <returns>
        /// <b>true</b> if the key is weak; otherwise, <b>false</b>.
        /// </returns>
        public abstract bool IsWeakKey(byte[] rgbKey);
    }
}
