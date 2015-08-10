namespace DotNetCrypt
{
    /// <summary>
    /// Indicates which endianness convention a cryptographic algorithm
    /// follows for conversions between bytes and words.
    /// </summary>
    public enum Endianness
    {
        /// <summary>
        /// Coversions are big endian.
        /// </summary>
        Big,
        /// <summary>
        /// Conversions are little endian.
        /// </summary>
        Little
    }
}
