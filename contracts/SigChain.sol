// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity ^0.8.20;

contract SigChain {
    error DeadlineExpired();
    error PayloadDoesNotMatch();
    error InvalidSigner(address sender);

    uint256 public cnt;
    uint256 public steps;

    address[] public signers;

    uint8[] internal sigV;
    bytes32[] internal sigR;
    bytes32[] internal sigS;

    bytes32 public immutable payloadHash;

    bytes32 public immutable DOMAIN_SEPARATOR;

    constructor(string memory payload, address[] memory _signers) {
        if (_signers.length == 0) revert();

        payloadHash = keccak256(abi.encodePacked(payload));

        signers = _signers;
        steps = _signers.length;

        DOMAIN_SEPARATOR = computeDomainSeparator();
    }

    function confirm(
        address sender,
        string calldata payload,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        if (deadline >= block.timestamp) revert DeadlineExpired();
        if (payloadHash != keccak256(abi.encodePacked(payload))) revert PayloadDoesNotMatch();

        address recoveredAddress = ecrecover(
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    DOMAIN_SEPARATOR,
                    keccak256(
                        abi.encode(
                            keccak256("Approve(address sender,string payload,uint256 deadline)"),
                            sender,
                            payloadHash,
                            deadline
                        )
                    )
                )
            ),
            v,
            r,
            s
        );

        if (recoveredAddress != signers[cnt]) revert InvalidSigner(recoveredAddress);

        sigV.push(v);
        sigR.push(r);
        sigS.push(s);

        unchecked {
            cnt++;
        }
    }

    function computeDomainSeparator() internal view returns (bytes32) {
        keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes("SigChain")),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
    }
}
