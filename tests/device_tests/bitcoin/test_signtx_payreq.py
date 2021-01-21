# This file is part of the Trezor project.
#
# Copyright (C) 2020 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

from collections import namedtuple

import pytest

from trezorlib import btc, messages, misc
from trezorlib.exceptions import TrezorFailure
from trezorlib.tools import parse_path

from ...tx_cache import TxCache
from .payment_req import CoinPurchaseMemo, TextMemo, make_payment_request

TX_API = TxCache("Testnet")

TXHASH_091446 = bytes.fromhex(
    "09144602765ce3dd8f4329445b20e3684e948709c5cdcaf12da3bb079c99448a"
)


pytestmark = pytest.mark.skip_t1


def case(id, *args, altcoin=False):
    if altcoin:
        marks = pytest.mark.altcoin
    else:
        marks = ()
    return pytest.param(*args, id=id, marks=marks)


inputs = [
    messages.TxInputType(
        address_n=parse_path("84'/1'/0'/0/0"),
        amount=12300000,
        prev_hash=TXHASH_091446,
        prev_index=0,
        script_type=messages.InputScriptType.SPENDWITNESS,
    )
]

outputs = [
    messages.TxOutputType(
        address="2N4Q5FhU2497BryFfUgbqkAJE87aKHUhXMp",
        amount=5000000,
        script_type=messages.OutputScriptType.PAYTOADDRESS,
    ),
    messages.TxOutputType(
        address="tb1q694ccp5qcc0udmfwgp692u2s2hjpq5h407urtu",
        script_type=messages.OutputScriptType.PAYTOADDRESS,
        amount=2000000,
    ),
    messages.TxOutputType(
        address_n=parse_path("84h/1h/0h/0/0"),
        amount=12300000 - 5000000 - 2000000 - 11000,
        script_type=messages.OutputScriptType.PAYTOWITNESS,
    ),
]

memos1 = [
    CoinPurchaseMemo(
        amount=1596360000,
        coin_name="Dash",
        slip44=5,
        address_n=parse_path("44'/5'/0'/1/0"),
    ),
]

memos2 = [
    CoinPurchaseMemo(
        amount=318960000,
        coin_name="Dash",
        slip44=5,
        address_n=parse_path("44'/5'/0'/1/0"),
    ),
    CoinPurchaseMemo(
        amount=83157080200,
        coin_name="Groestlcoin",
        slip44=17,
        address_n=parse_path("44'/17'/0'/0/3"),
    ),
]

PaymentRequestParams = namedtuple(
    "PaymentRequestParams", ["txo_indices", "hash_outputs", "memos", "get_nonce"]
)

hash_outputs0 = "9fe3c769ed70e83d1fd307674b2683551953b3d173412ba9a1ac8e9ec4bcde2c"
hash_outputs1 = "db869c1f6588157fc63ba87ab6f41adcf8667356be83fa21e70da2e4883507a3"
hash_outputs2 = "1ebcbff823fc6a5c776bd339f7e219c17a316c1df42eb83f8dd41d10d6cdb4b3"
hash_outputs01 = "a7775a6740ae11d61988a4025e8ca6831599a18b2a9a3e92a8594a1850977981"
hash_outputs12 = "b5fb10a40c3af6d73651c3954b694b4a6527b53bf20c212ed93987f4e9aabc2a"
hash_outputs012 = "a1a8eeb523b072104fd50d1aba6f220efe3a236a422bcb43d5cae7340583353d"


@pytest.mark.parametrize(
    "payment_request_params",
    (
        case(
            "out0",
            (PaymentRequestParams([0], hash_outputs0, memos1, get_nonce=True),),
            altcoin=True,
        ),
        case(
            "out1",
            (PaymentRequestParams([1], hash_outputs1, memos2, get_nonce=True),),
            altcoin=True,
        ),
        case("out2", (PaymentRequestParams([2], hash_outputs2, [], get_nonce=True),)),
        case(
            "out0+out1",
            (
                PaymentRequestParams([0], hash_outputs0, [], get_nonce=False),
                PaymentRequestParams([1], hash_outputs1, [], get_nonce=True),
            ),
        ),
        case(
            "out01",
            (
                PaymentRequestParams(
                    [0, 1],
                    hash_outputs01,
                    [TextMemo("Invoice #87654321.")],
                    get_nonce=True,
                ),
            ),
        ),
        case(
            "out012",
            (PaymentRequestParams([0, 1, 2], hash_outputs012, [], get_nonce=True),),
        ),
        case(
            "out12", (PaymentRequestParams([1, 2], hash_outputs12, [], get_nonce=True),)
        ),
    ),
)
def test_payment_request(client, payment_request_params):
    for txo in outputs:
        txo.payment_req_index = None

    payment_reqs = []
    for i, params in enumerate(payment_request_params):
        request_outputs = []
        for txo_index in params.txo_indices:
            outputs[txo_index].payment_req_index = i
            request_outputs.append(outputs[txo_index])
        nonce = misc.get_nonce(client) if params.get_nonce else None
        payment_reqs.append(
            make_payment_request(
                client,
                recipient_name="trezor.io",
                outputs=request_outputs,
                hash_outputs=bytes.fromhex(params.hash_outputs),
                memos=params.memos,
                nonce=nonce,
            )
        )

    _, serialized_tx = btc.sign_tx(
        client,
        "Testnet",
        inputs,
        outputs,
        prev_txes=TX_API,
        payment_reqs=payment_reqs,
    )

    assert (
        serialized_tx.hex()
        == "010000000001018a44999c07bba32df1cacdc50987944e68e3205b4429438fdde35c76024614090000000000ffffffff03404b4c000000000017a9147a55d61848e77ca266e79a39bfc85c580a6426c98780841e0000000000160014d16b8c0680c61fc6ed2e407455715055e41052f528b4500000000000160014b31dc2a236505a6cb9201fa0411ca38a254a7bf10247304402204adea8ae600878c5912310f546d600359f6cde8087ebd23f20f8acc7ecb2ede70220603334476c8fb478d8c539f027f9bff5f126e4438df757f9b4ba528adcb56c48012103adc58245cf28406af0ef5cc24b8afba7f1be6c72f279b642d85c48798685f86200000000"
    )

    # Ensure that the nonce has been invalidated.
    with pytest.raises(TrezorFailure, match="Invalid nonce in payment request"):
        btc.sign_tx(
            client,
            "Testnet",
            inputs,
            outputs,
            prev_txes=TX_API,
            payment_reqs=payment_reqs,
        )


def test_payment_req_wrong_amount(client):
    # Test wrong total amount in payment request.

    for txo in outputs:
        txo.payment_req_index = None

    outputs[0].payment_req_index = 0
    outputs[1].payment_req_index = 0
    payment_req = make_payment_request(
        client,
        recipient_name="trezor.io",
        outputs=outputs[:2],
        hash_outputs=bytes.fromhex(hash_outputs01),
        nonce=misc.get_nonce(client),
    )

    # Decrease the total amount of the payment request.
    payment_req.amount -= 1

    with pytest.raises(TrezorFailure, match="Invalid amount in payment request"):
        btc.sign_tx(
            client,
            "Testnet",
            inputs,
            outputs,
            prev_txes=TX_API,
            payment_reqs=[payment_req],
        )


@pytest.mark.altcoin
def test_payment_req_wrong_mac(client):
    # Test wrong MAC in payment request memo.

    for txo in outputs:
        txo.payment_req_index = None

    memo = CoinPurchaseMemo(
        amount=2234904000,
        coin_name="Dash",
        slip44=5,
        address_n=parse_path("44'/5'/0'/1/0"),
    )

    outputs[0].payment_req_index = 0
    outputs[1].payment_req_index = 0
    payment_req = make_payment_request(
        client,
        recipient_name="trezor.io",
        outputs=outputs[:2],
        hash_outputs=bytes.fromhex(hash_outputs01),
        memos=[memo],
        nonce=misc.get_nonce(client),
    )

    # Corrupt the MAC value.
    payment_req.memos[0].mac = bytearray(payment_req.memos[0].mac)
    payment_req.memos[0].mac[0] ^= 1

    with pytest.raises(TrezorFailure, match="Invalid address MAC"):
        btc.sign_tx(
            client,
            "Testnet",
            inputs,
            outputs,
            prev_txes=TX_API,
            payment_reqs=[payment_req],
        )


def test_payment_req_wrong_output(client):
    # Test wrong output in payment request.

    for txo in outputs:
        txo.payment_req_index = None

    outputs[0].payment_req_index = 0
    outputs[1].payment_req_index = 0
    payment_req = make_payment_request(
        client,
        recipient_name="trezor.io",
        outputs=outputs[:2],
        hash_outputs=bytes.fromhex(hash_outputs01),
        nonce=misc.get_nonce(client),
    )

    # Use a different address in the second output.
    fake_outputs = [
        outputs[0],
        messages.TxOutputType(
            address="tb1qnspxpr2xj9s2jt6qlhuvdnxw6q55jvygcf89r2",
            script_type=outputs[1].script_type,
            amount=outputs[1].amount,
            payment_req_index=outputs[1].payment_req_index,
        ),
        outputs[2],
    ]

    with pytest.raises(TrezorFailure, match="Invalid signature in payment request"):
        btc.sign_tx(
            client,
            "Testnet",
            inputs,
            fake_outputs,
            prev_txes=TX_API,
            payment_reqs=[payment_req],
        )
