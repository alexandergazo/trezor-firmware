from trezor import utils, wire
from trezor.crypto import hashlib, hmac

from .writers import write_bitcoin_varint, write_bytes_unchecked, write_uint32_le

if False:
    from apps.common.coininfo import CoinInfo
    from apps.common.keychain import Keychain

_ADDRESS_MAC_KEY_PATH = [b"SLIP-0024", b"Address MAC key"]


def check_address_mac(
    address: bytes, mac: bytes, coin: CoinInfo, keychain: Keychain
) -> None:
    expected_mac = get_address_mac(address, coin, keychain)
    if len(mac) != hashlib.sha256.digest_size or not utils.consteq(expected_mac, mac):
        raise wire.DataError("Invalid address MAC.")


def get_address_mac(address: bytes, coin: CoinInfo, keychain: Keychain) -> bytes:
    # k = Key(m/"SLIP-0024"/"Address MAC key")
    node = keychain.derive_slip21(_ADDRESS_MAC_KEY_PATH)

    # mac = HMAC-SHA256(key = k, msg = slip44 || address)
    mac = utils.HashWriter(hmac(hmac.SHA256, node.key()))
    write_uint32_le(mac, coin.slip44)
    write_bitcoin_varint(mac, len(address))
    write_bytes_unchecked(mac, address)
    return mac.get_digest()
