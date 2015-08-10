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
    /// Abstract base class for implementations of Ross Anderson, Eli Biham and
    /// Lars Knudsen's Serpent algorithm.
    /// </summary>
    public abstract class Serpent : SymmetricAlgorithmBase
    {
        static private readonly KeySizes[] _legalBlockSizes = new[] { new KeySizes(0x80, 0x80, 0) };
        static private readonly KeySizes[] _legalKeySizes = new[] { new KeySizes(0x80, 0x100, 0x40) };

        /// <summary>
        /// Initializes a new instance of the <see cref="Serpent"/> class.
        /// </summary>
        protected Serpent()
        {
            KeySizeValue = 0x80;
            BlockSizeValue = 0x80;
            FeedbackSizeValue = BlockSizeValue;
            LegalBlockSizesValue = _legalBlockSizes;
            LegalKeySizesValue = _legalKeySizes;
        }

        /// <overloads>
        /// Creates an instance of a cryptographic object to perform the
        /// <see cref="Serpent" /> algorithm.
        /// </overloads>
        /// <summary>
        /// Creates an instance of a cryptographic object to perform the
        /// <see cref="Serpent" /> algorithm.
        /// </summary>
        /// <returns>
        /// A cryptographic object.
        /// </returns>
        static public new Serpent Create()
        {
            return Create("DotNetCrypt.Serpent");
        }

        /// <summary>
        /// Creates an instance of a cryptographic object to perform the
        /// specified implementation of the <see cref="Serpent" /> algorithm.
        /// </summary>
        /// <param name="algName">
        /// The name of the specified implementation of <see cref="Serpent"/>
        /// to use.
        /// </param>
        /// <returns>
        /// A cryptographic object.
        /// </returns>
        static public new Serpent Create(string algName)
        {
            return (Serpent)CryptoConfig.CreateFromName(algName);
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
        public override bool IsWeakKey(byte[] rgbKey)
        {
            return false;
        }
    }
}
