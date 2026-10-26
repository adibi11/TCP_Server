def calculate_crc(data: bytes) -> int:
    """
    Calculate a 32-bit CRC checksum for the given data.

    Uses the polynomial 0x04C11DB7 with an initial CRC value of zero.
    Each byte is processed using a non-reflected, bit-by-bit algorithm.

    After processing the data, its length is incorporated into the CRC
    in little-endian byte order. The final CRC value is bitwise inverted.

    Args:
        data (bytes): The data for which to calculate the checksum.

    Returns:
        int: The calculated unsigned 32-bit CRC checksum.
    """
    polynomial = 0x04C11DB7
    crc = 0

    def update(crc: int, byte: int) -> int:
        """
        Update the CRC accumulator with a single byte.

        Args:
            crc (int): The current CRC accumulator.
            byte (int): The next byte to process (0-255).

        Returns:
            int: The updated 32-bit CRC accumulator.
        """
        crc ^= byte << 24

        # Process each of the eight bits using polynomial division.
        for _ in range(8):
            if crc & 0x80000000:
                crc = ((crc << 1) ^ polynomial) & 0xFFFFFFFF
            else:
                crc = (crc << 1) & 0xFFFFFFFF

        return crc

    # Calculate the CRC over the file content.
    for byte in data:
        crc = update(crc, byte)

    # Incorporate the original data length, least significant byte first.
    length = len(data)

    while length > 0:
        crc = update(crc, length & 0xFF)
        length >>= 8

    # Invert the bits and return the unsigned 32-bit result.
    return (~crc) & 0xFFFFFFFF
