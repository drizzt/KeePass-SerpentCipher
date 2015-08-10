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
    /// Specfies the method used in counter
    /// (<see cref="ExtendedCipherMode.CTR" />) mode to combine the counter
    /// with the "nonce" (or initialization vector).
    /// </summary>
    public enum NonceCombinationMode
    {
        /// <summary>
        /// The counter and the nonce are combined using a bitwise
        /// exclusive OR operation. This option, which is the default in this
        /// implementation, allows for the greatest length of encrypted
        /// message.
        /// </summary>
        Xor = 0,
        /// <summary>
        /// THe counter and the nonce are combined using concatenation This
        /// option restricts the length of the message that can be processed
        /// in a way that depends onte length of the nonce.
        /// </summary>
        Concatenate,
        /// <summary>
        /// The counter and the nonce are combined using addition. This option
        /// restricts the length of the message that can be processed in a way
        /// that depends on the actual value of the nonce.
        /// </summary>
        Add
    }
}