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

namespace DotNetCrypt
{
    /// <summary>
    /// Specifies the direction of the cryptographic operation.
    /// </summary>
    public enum TransformDirection
    {
        /// <summary>
        /// Data is to be encrypted.
        /// </summary>
        Encrypt,
        /// <summary>
        /// Data is to be decrypted.
        /// </summary>
        Decrypt
    }
}
