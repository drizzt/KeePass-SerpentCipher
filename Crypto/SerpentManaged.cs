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
    /// Accesses the managed version of the <see cref="Serpent" /> algorithm.
    /// This class cannot be inherited.
    /// </summary>
    public sealed class SerpentManaged : Serpent
    {
        /// <overloads>
        /// Creates a symmetric decryptor object.
        /// </overloads>
        /// <summary>
        /// Creates a symmetric decryptor object with the specified
        /// <see cref="P:System.Security.Cryptography.SymmetricAlgorithm.Key"/>
        /// property and initialization vector
        /// (<see cref="P:System.Security.Cryptography.SymmetricAlgorithm.IV"/>).
        /// </summary>
        /// <returns>
        /// A symmetric decryptor object.
        /// </returns>
        /// <param name="rgbKey">
        /// The secret key to use for the symmetric algorithm.
        /// </param>
        /// <param name="rgbIV">
        /// The initialization vector to use for the symmetric algorithm. 
        /// </param>
        // ReSharper disable InconsistentNaming
        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        // ReSharper restore InconsistentNaming
        {
            return Utils.NewEncryptor(this, typeof(SerpentManagedTransform), rgbKey, ExtendedMode, rgbIV, TransformDirection.Decrypt);
        }

        /// <overloads>
        /// Creates a symmetric encryptor object.
        /// </overloads>
        /// <summary>
        /// Creates a symmetric encryptor object with the specified
        /// <see cref="P:System.Security.Cryptography.SymmetricAlgorithm.Key"/>
        /// property and initialization vector
        /// (<see cref="P:System.Security.Cryptography.SymmetricAlgorithm.IV"/>).
        /// </summary>
        /// <returns>
        /// A symmetric encryptor object.
        /// </returns>
        /// <param name="rgbKey">
        /// The secret key to use for the symmetric algorithm. 
        /// </param>
        /// <param name="rgbIV">
        /// The initialization vector to use for the symmetric algorithm. 
        /// </param>
        // ReSharper disable InconsistentNaming
        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        // ReSharper restore InconsistentNaming
        {
            return Utils.NewEncryptor(this, typeof(SerpentManagedTransform), rgbKey, ExtendedMode, rgbIV, TransformDirection.Encrypt);
        }
    }
}
