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
    /// <summary>
    /// An abstract base class for managed implementations of
    /// <see cref="ICryptoTransform" />.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This class deals with the various forms of padding available. Unlike
    /// the classes built into the .NET framework, however, for modes which
    /// effectively operate in stream cipher mode (CFB, OFB), it is
    /// permissible to encrypt a message which is not an exact number of
    /// bytes without specifying a padding mode other than
    /// <see cref="System.Security.Cryptography.PaddingMode.None" />
    /// </para>
    /// <para>
    /// It also takes into account the cipher mode to be used. For increased
    /// compatibility with other systems, counter mode (CTR) is also supported
    /// via the <see cref="ExtendedCipherMode" /> enumeration.
    /// </para>
    /// </remarks>
    public abstract class ManagedTransformBase : ICryptoTransform
    {
        private delegate uint[] BytesToWords(byte[] bytes);
        private delegate void WriteWordsIntoBytes(uint[] words, byte[] bytes);

        private byte[] _depadBuffer;
        private byte[] _feedbackValue;
        private byte[] _iv;
        private byte[] _counter;
        private bool _initial;
        private int _counterSize;
        private readonly TransformDirection _transformDirection;
        private readonly int _registerShiftSize;
        private readonly BytesToWords _bytesToWords;
        private readonly WriteWordsIntoBytes _writeWordsIntoBytes;

        internal Endianness Endianness { get; set; }

        /// <summary>
        /// Creates a new managed transform instance, reading necessary
        /// setting values from the provided <see cref="ISymmetricAlgorithm" />
        /// instance.
        /// </summary>
        /// <param name="algorithm">
        /// A <see cref="ISymmetricAlgorithm" /> instance from which to take
        /// setting values.
        /// </param>
        /// <param name="rgbIv">
        /// The initialization vector to use.
        /// </param>
        /// <param name="transformDirection">
        /// The direction of the transform (encryption or decryption).
        /// </param>
        /// <param name="endianness">
        /// The endianness convention for the algorithm.
        /// </param>
        protected ManagedTransformBase(ISymmetricAlgorithm algorithm, byte[] rgbIv, TransformDirection transformDirection, Endianness endianness)
        {
            Endianness = endianness;
            _bytesToWords = endianness == Endianness.Little
                                ? (BytesToWords)Utils.BytesToWordsLittleEndian
                                : Utils.BytesToWordsBigEndian;
            _writeWordsIntoBytes = endianness == Endianness.Little
                                ? (WriteWordsIntoBytes)Utils.WriteWordsIntoBytesLittleEndian
                                : Utils.WriteWordsIntoBytesBigEndian;
            PaddingMode = algorithm.Padding;
            BlockSizeBytes = algorithm.BlockSize >> 3;
            Mode = algorithm.ExtendedMode;
            NonceCombinationMode = algorithm.NonceCombinationMode;
            _registerShiftSize = algorithm.RegisterShiftSize;
            _feedbackValue = new byte[BlockSizeBytes];
            _iv = new byte[BlockSizeBytes];
            if (rgbIv != null)
            {
                rgbIv.CopyTo(_feedbackValue, 0);
                rgbIv.CopyTo(_iv, 0);
                if (Mode == ExtendedCipherMode.CTR)
                {
                    switch (NonceCombinationMode)
                    {
                        case NonceCombinationMode.Concatenate:
                            _counterSize = BlockSizeBytes - rgbIv.Length;
                            _counter = new byte[_counterSize];
                            break;
                        case NonceCombinationMode.Xor:
                            _counterSize = BlockSizeBytes;
                            _counter = new byte[_counterSize];
                            break;
                        case NonceCombinationMode.Add:
                            _counterSize = BlockSizeBytes;
                            _counter = (byte[])_feedbackValue.Clone();
                            break;
                    }
                    _initial = true;
                }
            }
            _transformDirection = transformDirection;
        }

        /// <summary>
        /// Gets or sets the block size for this algorithm, in bytes.
        /// </summary>
        protected int BlockSizeBytes { get; set; }

        /// <summary>
        /// Gets or sets the padding mode to be used to round a message up to
        /// the nearest block boundary.
        /// </summary>
        protected PaddingMode PaddingMode { get; set; }

        /// <summary>
        /// Gets or sets the block cipher chaining mode used in encrypting
        /// messages.
        /// </summary>
        protected ExtendedCipherMode Mode { get; set; }

        /// <summary>
        /// Gets or sets the method used for combining the counter with the
        /// nonce in counter (<see cref="ExtendedCipherMode.CTR"/>) mode.
        /// </summary>
        protected NonceCombinationMode NonceCombinationMode { get; set; }

        #region ICryptoTransform Members

        /// <summary>
        /// Performs application-defined tasks associated with freeing,
        /// releasing, or resetting unmanaged resources.
        /// </summary>
        /// <filterpriority>2</filterpriority>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Transforms the specified region of the input byte array and copies
        /// the resulting transform to the specified region of the output byte
        /// array.
        /// </summary>
        /// <returns>
        /// The number of bytes written.
        /// </returns>
        /// <param name="inputBuffer">
        /// The input for which to compute the transform.
        /// </param>
        /// <param name="inputOffset">
        /// The offset into the input byte array from which to begin using data. 
        /// </param>
        /// <param name="inputCount">
        /// The number of bytes in the input byte array to use as data. 
        /// </param>
        /// <param name="outputBuffer">
        /// The output to which to write the transform. 
        /// </param>
        /// <param name="outputOffset">
        /// The offset into the output byte array from which to begin writing
        /// data. 
        /// </param>
        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer,
                                  int outputOffset)
        {
            if (inputBuffer == null)
            {
                throw new ArgumentNullException("inputBuffer");
            }
            if (outputBuffer == null)
            {
                throw new ArgumentNullException("outputBuffer");
            }
            if (inputOffset < 0)
            {
                throw new ArgumentOutOfRangeException("inputOffset");
            }
            if (((inputCount <= 0) || ((inputCount % InputBlockSize) != 0)) || (inputCount > inputBuffer.Length))
            {
                throw new ArgumentException();
            }
            if ((inputBuffer.Length - inputCount) < inputOffset)
            {
                throw new ArgumentException();
            }
            if (_transformDirection == TransformDirection.Encrypt)
            {
                return EncryptData(inputBuffer, inputOffset, inputCount, ref outputBuffer, outputOffset, PaddingMode,
                                   false);
            }
            if ((PaddingMode == PaddingMode.Zeros) || (PaddingMode == PaddingMode.None))
            {
                return DecryptData(inputBuffer, inputOffset, inputCount, ref outputBuffer, outputOffset, PaddingMode,
                                   false);
            }
            if (_depadBuffer == null)
            {
                _depadBuffer = new byte[InputBlockSize];
                int num = inputCount - InputBlockSize;
                Array.Copy(inputBuffer, inputOffset + num, _depadBuffer, 0, InputBlockSize);
                return DecryptData(inputBuffer, inputOffset, num, ref outputBuffer, outputOffset, PaddingMode, false);
            }
            DecryptData(_depadBuffer, 0, _depadBuffer.Length, ref outputBuffer, outputOffset, PaddingMode, false);
            outputOffset += OutputBlockSize;
            int num3 = inputCount - InputBlockSize;
            Array.Copy(inputBuffer, inputOffset + num3, _depadBuffer, 0, InputBlockSize);
            int num2 = DecryptData(inputBuffer, inputOffset, num3, ref outputBuffer, outputOffset, PaddingMode, false);
            return (OutputBlockSize + num2);
        }

        /// <summary>
        /// Transforms the specified region of the specified byte array.
        /// </summary>
        /// <returns>
        /// The computed transform.
        /// </returns>
        /// <param name="inputBuffer">
        /// The input for which to compute the transform. 
        /// </param>
        /// <param name="inputOffset">
        /// The offset into the byte array from which to begin using data. 
        /// </param>
        /// <param name="inputCount">
        /// The number of bytes in the byte array to use as data. 
        /// </param>
        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (inputBuffer == null)
            {
                throw new ArgumentNullException("inputBuffer");
            }
            if (inputOffset < 0)
            {
                throw new ArgumentOutOfRangeException("inputOffset");
            }
            if ((inputCount < 0) || (inputCount > inputBuffer.Length))
            {
                throw new ArgumentException();
            }
            if ((inputBuffer.Length - inputCount) < inputOffset)
            {
                throw new ArgumentException();
            }
            if (_transformDirection == TransformDirection.Encrypt)
            {
                byte[] buffer = null;
                EncryptData(inputBuffer, inputOffset, inputCount, ref buffer, 0, PaddingMode, true);
                Reset();
                return buffer;
            }
            if (!Utils.IsStreamMode(Mode) && (inputCount % InputBlockSize) != 0)
            {
                throw new CryptographicException("The inputCount must be a multiple of the InputBlockSize");
            }
            if (_depadBuffer == null)
            {
                byte[] buffer2 = null;
                DecryptData(inputBuffer, inputOffset, inputCount, ref buffer2, 0, PaddingMode, true);
                Reset();
                return buffer2;
            }
            var dst = new byte[_depadBuffer.Length + inputCount];
            Array.Copy(_depadBuffer, 0, dst, 0, _depadBuffer.Length);
            Array.Copy(inputBuffer, inputOffset, dst, _depadBuffer.Length, inputCount);
            byte[] outputBuffer = null;
            DecryptData(dst, 0, dst.Length, ref outputBuffer, 0, PaddingMode, true);
            Reset();
            return outputBuffer;
        }

        #endregion

        /// <summary>
        /// <para>
        /// Dispose(bool disposing) executes in two distinct scenarios.
        /// If disposing equals true, the method has been called directly
        /// or indirectly by a user's code. Managed and unmanaged resources
        /// can be disposed.
        /// </para>
        /// <para>
        /// If disposing equals false, the method has been called by the 
        /// runtime from inside the finalizer and you should not reference 
        /// other objects. Only unmanaged resources can be disposed.
        /// </para>
        /// </summary>
        /// <param name="disposing">
        /// Indicates whether this method is being called by a user's code.
        /// </param>
        protected virtual void Dispose(bool disposing)
        {
        }

        private int EncryptData(byte[] inputBuffer, int inputOffset, int inputCount, ref byte[] outputBuffer,
                                           int outputOffset, PaddingMode paddingMode, bool final)
        {
            if (inputBuffer.Length < (inputOffset + inputCount))
            {
                throw new CryptographicException();
            }

            int inputBlockSize = InputBlockSize;
            int blockSizeBytes = BlockSizeBytes;
            ExtendedCipherMode mode = Mode;
            int partialBlockSize = inputCount % inputBlockSize;
            int paddingSizeRequired = 0;
            byte[] data;
            if (final)
            {
                switch (paddingMode)
                {
                    case PaddingMode.None:
                        if (partialBlockSize != 0 & !Utils.IsStreamMode(mode))
                        {
                            throw new CryptographicException();
                        }
                        break;
                    case PaddingMode.PKCS7:
                        paddingSizeRequired = inputBlockSize - partialBlockSize;
                        break;
                    case PaddingMode.Zeros:
                        if (partialBlockSize != 0)
                        {
                            paddingSizeRequired = inputBlockSize - partialBlockSize;
                        }
                        break;
                    case PaddingMode.ANSIX923:
                        paddingSizeRequired = inputBlockSize - partialBlockSize;
                        break;
                    case PaddingMode.ISO10126:
                        paddingSizeRequired = inputBlockSize - partialBlockSize;
                        break;
                }

                if (paddingSizeRequired != 0)
                {
                    data = new byte[paddingSizeRequired];
                    switch (paddingMode)
                    {
                        case PaddingMode.PKCS7:
                            int index = 0;
                            while (index < paddingSizeRequired)
                            {
                                data[index] = (byte)paddingSizeRequired;
                                index++;
                            }
                            break;

                        case PaddingMode.ANSIX923:
                            data[paddingSizeRequired - 1] = (byte)paddingSizeRequired;
                            break;

                        case PaddingMode.ISO10126:
                            Utils.RandomNumberGeneratorSingleton.GetBytes(data);
                            data[paddingSizeRequired - 1] = (byte)paddingSizeRequired;
                            break;
                    }
                    var tempBuffer = new byte[inputCount + paddingSizeRequired];
                    Array.Copy(inputBuffer, 0, tempBuffer, 0, inputCount);
                    data.CopyTo(tempBuffer, inputCount);
                    inputBuffer = tempBuffer;
                }
            }
            if (outputBuffer == null)
            {
                outputBuffer = new byte[inputCount + paddingSizeRequired];
                outputOffset = 0;
            }
            else if ((outputBuffer.Length - outputOffset) < (inputCount + paddingSizeRequired))
            {
                throw new CryptographicException();
            }

            int byteCount = 0;
            var tempState = new byte[blockSizeBytes];
            int count = blockSizeBytes;
            if (mode == ExtendedCipherMode.CFB)
            {
                count = _registerShiftSize == 0 ? 1 : _registerShiftSize;
            }

            while (byteCount < inputCount + paddingSizeRequired)
            {
                var block = new byte[blockSizeBytes];
                int bytesToCopy = count;
                if (blockSizeBytes + inputOffset > inputBuffer.Length) bytesToCopy = inputBuffer.Length - inputOffset;
                Array.Copy(inputBuffer, inputOffset, block, 0, bytesToCopy);

                switch (mode)
                {
                    case ExtendedCipherMode.ECB:
                        EncryptBlock(block);
                        break;
                    case ExtendedCipherMode.CBC:
                        for (int i = 0; i < blockSizeBytes; i++) block[i] ^= _feedbackValue[i];
                        EncryptBlock(block);
                        block.CopyTo(_feedbackValue, 0);
                        break;
                    case ExtendedCipherMode.CFB:
                        Array.Copy(_feedbackValue, count, tempState, 0, blockSizeBytes - count);
                        EncryptBlock(_feedbackValue);
                        for (int i = 0; i < count; i++) _feedbackValue[i] ^= block[i];
                        Array.Copy(_feedbackValue, 0, block, 0, count);
                        tempState.CopyTo(_feedbackValue, 0);
                        Array.Copy(block, 0, _feedbackValue, blockSizeBytes - count, count);
                        break;
                    case ExtendedCipherMode.OFB:
                        Array.Copy(_feedbackValue, count, tempState, 0, blockSizeBytes - count);
                        EncryptBlock(_feedbackValue);
                        for (int i = 0; i < count; i++) block[i] ^= _feedbackValue[i];
                        Array.Copy(_feedbackValue, 0, _feedbackValue, blockSizeBytes - count, count);
                        Array.Copy(tempState, 0, _feedbackValue, 0, blockSizeBytes - count);
                        break;
                    case ExtendedCipherMode.CTS:
                        throw new NotImplementedException();
                    case ExtendedCipherMode.CTR:
                        if (_initial)
                        {
                            _initial = false;
                        }
                        else
                        {
                            IncrementCounter();
                        }
                        switch (NonceCombinationMode)
                        {
                            case NonceCombinationMode.Concatenate:
                                _iv.CopyTo(_feedbackValue, 0);
                                _counter.CopyTo(_feedbackValue, blockSizeBytes - _counterSize);
                                break;
                            case NonceCombinationMode.Add:
                                _counter.CopyTo(_feedbackValue, 0);
                                break;
                            case NonceCombinationMode.Xor:
                                _iv.CopyTo(_feedbackValue, 0);
                                for (int index = 0; index < _counterSize; index++)
                                {
                                    _feedbackValue[blockSizeBytes - _counterSize + index] ^= _counter[index];
                                }
                                break;
                        }
                        EncryptBlock(_feedbackValue);
                        for (int i = 0; i < blockSizeBytes; i++) block[i] ^= _feedbackValue[i];
                        break;
                }

                if (outputOffset + count > outputBuffer.Length) count = outputBuffer.Length - outputOffset;
                Array.Copy(block, 0, outputBuffer, outputOffset, count);

                byteCount += count;
                inputOffset += count;
                outputOffset += count;
            }

            if (Utils.IsStreamMode(mode) && outputBuffer.Length > inputCount && paddingMode == PaddingMode.None)
            {
                var result = new byte[inputCount];
                Array.Copy(outputBuffer, 0, result, 0, inputCount);
                outputBuffer = result;
            }

            return inputCount;
        }

        private void IncrementCounter()
        {
            if (_counter[_counterSize - 1] < 255)
            {
                _counter[_counterSize - 1]++;
                return;
            }
            int index = _counterSize - 1;
            while (_counter[index] == 255)
            {
                _counter[index--] = 0;
                if (index < 0)
                {
                    throw new CryptographicException();
                }
            }
            _counter[index]++;
        }

        /// <summary>
        /// Encrypts a single block of bytes, writing the result into the
        /// provided array.
        /// </summary>
        /// <param name="block">
        /// The block of bytes to be encrypted.
        /// </param>
        protected virtual void EncryptBlock(byte[] block)
        {
            uint[] words = _bytesToWords(block);
            Encrypt(words);
            _writeWordsIntoBytes(words, block);
        }

        /// <summary>
        /// When implemented in a derived class, performs the encryption
        /// transformation on a block of bytes that have been translated into
        /// words using the endianness convention of the algorithm.
        /// </summary>
        /// <param name="plain">
        /// The words to encrypt.
        /// </param>
        [CLSCompliant(false)]
        protected internal virtual void Encrypt(uint[] plain) {}

        /// <summary>
        /// Decrypts a single block of bytes, writing the result into the
        /// provided array.
        /// </summary>
        /// <param name="block">
        /// The block of bytes to be decrypted.
        /// </param>
        protected virtual void DecryptBlock(byte[] block)
        {
            uint[] words = _bytesToWords(block);
            Decrypt(words);
            _writeWordsIntoBytes(words, block);
        }

        /// <summary>
        /// When implemented in a derived class, performs the decryption
        /// transformation on a block of bytes that have been translated into
        /// words using the endianness convention of the algorithm.
        /// </summary>
        /// <param name="cipher">
        /// The words to decrypt.
        /// </param>
        [CLSCompliant(false)]
        protected internal virtual void Decrypt(uint[] cipher) {}

        private int DecryptData(byte[] inputBuffer, int inputOffset, int inputCount, ref byte[] outputBuffer,
                                           int outputOffset, PaddingMode paddingMode, bool final)
        {
            if (inputBuffer.Length < (inputOffset + inputCount))
            {
                throw new CryptographicException();
            }
            if (outputBuffer == null)
            {
                outputBuffer = new byte[inputCount];
                outputOffset = 0;
            }
            else if ((outputBuffer.Length - outputOffset) < inputCount)
            {
                throw new CryptographicException();
            }

            int inputBlockSize = InputBlockSize;
            int blockSizeBytes = BlockSizeBytes;
            int byteCount = 0;
            var tempState = new byte[blockSizeBytes];
            int count = blockSizeBytes;
            if (Mode == ExtendedCipherMode.CFB)
            {
                count = _registerShiftSize == 0 ? 1 : _registerShiftSize;
            }

            while (byteCount < inputCount)
            {
                var block = new byte[blockSizeBytes];
                int bytesToCopy = count;
                if (blockSizeBytes + inputOffset > inputBuffer.Length) bytesToCopy = inputBuffer.Length - inputOffset;
                Array.Copy(inputBuffer, inputOffset, block, 0, bytesToCopy);

                switch (Mode)
                {
                    case ExtendedCipherMode.ECB:
                        DecryptBlock(block);
                        break;
                    case ExtendedCipherMode.CBC:
                        block.CopyTo(tempState, 0);
                        DecryptBlock(block);
                        for (int i = 0; i < blockSizeBytes; i++) block[i] ^= _feedbackValue[i];
                        tempState.CopyTo(_feedbackValue, 0);
                        break;
                    case ExtendedCipherMode.CFB:
                        Array.Copy(block, 0, tempState, blockSizeBytes - count, count);
                        Array.Copy(_feedbackValue, count, tempState, 0, blockSizeBytes - count);
                        EncryptBlock(_feedbackValue);
                        for (int i = 0; i < count; i++) _feedbackValue[i] ^= block[i];
                        Array.Copy(_feedbackValue, 0, block, 0, count);
                        tempState.CopyTo(_feedbackValue, 0);
                        break;
                    case ExtendedCipherMode.OFB:
                        Array.Copy(_feedbackValue, count, tempState, 0, blockSizeBytes - count);
                        EncryptBlock(_feedbackValue);
                        for (int i = 0; i < count; i++) block[i] ^= _feedbackValue[i];
                        Array.Copy(_feedbackValue, 0, _feedbackValue, blockSizeBytes - count, count);
                        Array.Copy(tempState, 0, _feedbackValue, 0, blockSizeBytes - count);
                        break;
                    case ExtendedCipherMode.CTS:
                        throw new NotImplementedException();
                    case ExtendedCipherMode.CTR:
                        if (_initial)
                        {
                            _initial = false;
                        }
                        else
                        {
                            IncrementCounter();
                        }
                        switch (NonceCombinationMode)
                        {
                            case NonceCombinationMode.Concatenate:
                                _iv.CopyTo(_feedbackValue, 0);
                                _counter.CopyTo(_feedbackValue, blockSizeBytes - _counterSize);
                                break;
                            case NonceCombinationMode.Add:
                                _counter.CopyTo(_feedbackValue, 0);
                                break;
                            case NonceCombinationMode.Xor:
                                _iv.CopyTo(_feedbackValue, 0);
                                for (int index = 0; index < _counterSize; index++)
                                {
                                    _feedbackValue[blockSizeBytes - _counterSize + index] ^= _counter[index];
                                }
                                break;
                        }
                        EncryptBlock(_feedbackValue);
                        for (int i = 0; i < blockSizeBytes; i++) block[i] ^= _feedbackValue[i];
                        break;
                }

                if (outputOffset + count > outputBuffer.Length) count = outputBuffer.Length - outputOffset;
                Array.Copy(block, 0, outputBuffer, outputOffset, count);

                byteCount += count;
                inputOffset += count;
                outputOffset += count;
            }

            if (Utils.IsStreamMode(Mode) && outputBuffer.Length > inputCount)
            {
                var tempBuffer = new byte[inputCount];
                Array.Copy(outputBuffer, 0, tempBuffer, 0, inputCount);
                outputBuffer = tempBuffer;
            }

            int result = inputCount;
            if (!final) return inputCount;
            int paddingSize = 0;
            switch (paddingMode)
            {
                case PaddingMode.PKCS7:
                    paddingSize = outputBuffer[inputCount - 1];
                    if (((paddingSize > outputBuffer.Length) || (paddingSize > inputBlockSize)) || (paddingSize <= 0))
                    {
                        throw new CryptographicException();
                    }
                    for (int index = 2; index <= paddingSize; index++)
                    {
                        if (outputBuffer[inputCount - index] != paddingSize)
                        {
                            throw new CryptographicException();
                        }
                    }
                    break;
                case PaddingMode.ANSIX923:
                    paddingSize = outputBuffer[inputCount - 1];
                    if (((paddingSize > outputBuffer.Length) || (paddingSize > inputBlockSize)) || (paddingSize <= 0))
                    {
                        throw new CryptographicException();
                    }
                    for (int index = 2; index <= paddingSize; index++)
                    {
                        if (outputBuffer[inputCount - index] != 0)
                        {
                            throw new CryptographicException();
                        }
                    }
                    break;
                case PaddingMode.ISO10126:
                    paddingSize = outputBuffer[inputCount - 1];
                    if (((paddingSize > outputBuffer.Length) || (paddingSize > inputBlockSize)) || (paddingSize <= 0))
                    {
                        throw new CryptographicException();
                    }
                    break;
            }
            if (paddingSize > 0)
            {
                var tempBuffer = new byte[outputBuffer.Length - paddingSize];
                Array.Copy(outputBuffer, 0, tempBuffer, 0, outputBuffer.Length - paddingSize);
                outputBuffer = tempBuffer;
                result -= paddingSize;
            }
            return result;
        }

        /// <summary>
        /// Clears all potentially sensitive data stores.
        /// </summary>
        protected internal virtual void Reset()
        {
            if (_depadBuffer != null)
            {
                Array.Clear(_depadBuffer, 0, _depadBuffer.Length);
                _depadBuffer = null;
            }
            if (_feedbackValue != null)
            {
                Array.Clear(_feedbackValue, 0, _feedbackValue.Length);
                _feedbackValue = null;
            }
            if (_iv != null)
            {
                Array.Clear(_iv, 0, _iv.Length);
                _iv = null;
            }
            if (_counter != null)
            {
                Array.Clear(_counter, 0, _counter.Length);
                _counter = null;
            }
            _counterSize = 0;
        }

        /// <summary>
        /// Gets the input block size.
        /// </summary>
        /// <returns>
        /// The size of the input data blocks in bytes.
        /// </returns>
        public virtual int InputBlockSize
        {
            get { return BlockSizeBytes; }
        }

        /// <summary>
        /// Gets the output block size.
        /// </summary>
        /// <returns>
        /// The size of the output data blocks in bytes.
        /// </returns>
        public virtual int OutputBlockSize
        {
            get { return BlockSizeBytes; }
        }

        /// <summary>
        /// Gets a value indicating whether multiple blocks can be transformed.
        /// </summary>
        /// <returns>
        /// true if multiple blocks can be transformed; otherwise, false.
        /// </returns>
        public virtual bool CanTransformMultipleBlocks
        {
            get { return true; }
        }

        /// <summary>
        /// Gets a value indicating whether the current transform can be reused.
        /// </summary>
        /// <returns>
        /// true if the current transform can be reused; otherwise, false.
        /// </returns>
        public virtual bool CanReuseTransform
        {
            get { return Mode == ExtendedCipherMode.ECB; }
        }

        /// <summary>
        /// Releases all resources used by the
        /// <see cref="ManagedTransformBase" /> class.
        /// </summary>
        public void Clear()
        {
            Reset();
            Dispose();
        }
    }
}