using System;
using System.Security.Cryptography;

namespace DotNetCrypt
{
    /// <summary>
    /// An abstract base class for managed implementations of
    /// <see cref="HashAlgorithm" />.
    /// </summary>
    public abstract class ManagedHashAlgorithmBase : HashAlgorithm
    {
        internal int Count { get; set; }
        internal byte[] FinalBlock { get; set; }

        /// <summary>
        /// Routes data written to the
        /// object into the hash algorithm for computing the hash.
        /// </summary>
        /// <param name="array">
        /// The input to compute the hash code for. 
        /// </param>
        /// <param name="ibStart">
        /// The offset into the byte array from which to begin using data. 
        /// </param>
        /// <param name="cbSize">
        /// The number of bytes in the byte array to use as data. 
        /// </param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            int count = cbSize;
            int index = ibStart;
            var partialBlockBytes = (int)(Count & 0x3fL);
            Count += count;
            if ((partialBlockBytes > 0) && ((partialBlockBytes + count) >= InputBlockSize))
            {
                index += InputBlockSize - partialBlockBytes;
                count -= InputBlockSize - partialBlockBytes;
                TransformBlock(array, index);
            }
            while (count >= InputBlockSize)
            {
                TransformBlock(array, index);
                index += InputBlockSize;
                count -= InputBlockSize;
            }
            FinalBlock = new byte[0];
            if (count > 0)
            {
                FinalBlock = new byte[count];
                Array.Copy(array, index, FinalBlock, 0, count);
            }
        }

        /// <summary>
        /// When implemented in a derived class, transforms a single block of
        /// bytes using the chosen hash algorithm.
        /// </summary>
        /// <param name="array">
        /// An array containing the block of bytes.
        /// </param>
        /// <param name="ibStart">
        /// The offset of the start of the block within the array.
        /// </param>
        protected abstract void TransformBlock(byte[] array, int ibStart);
    }
}
