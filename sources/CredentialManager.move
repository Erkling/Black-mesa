module black_mesa_addr::CredentialManager {
    use std::signer;
    use std::option;
    use std::vector;

    /// Structure to represent a verifiable credential
    struct Credential has key {
        issuer: address,        // Issuer's account address
        recipient: address,     // Recipient's account address
        data: vector<u8>,       // Credential data (e.g., purpose or reason)
        personal_info: option<PersonalInfo>, // Personal details (if included)
        issued_at: u64,         // Issuance timestamp
    }

    /// Issue a new credential
    public fun issue_credential(
        issuer: &signer,
        recipient: address,
        data: vector<u8>,
        personal_info: option<PersonalInfo>,
        issued_at: u64
    ) acquires Credential {
        let recipient_addr = recipient;

        // Ensure a credential doesn't already exist for this recipient
        assert!(exists<Credential>(recipient_addr) == false, 2);

        // Create and store the credential
        move_to(&recipient, Credential { 
            issuer: signer::address_of(issuer), 
            recipient: recipient_addr, 
            data, 
            personal_info, 
            issued_at 
        });
    }

    /// Retrieve credential details
    public fun get_credential(recipient: address): Credential acquires Credential {
        borrow_global<Credential>(recipient)
    }

    /// Verify a credential
    public fun verify_credential(recipient: address, issuer: address): bool acquires Credential {
        let credential = borrow_global<Credential>(recipient);
        credential.issuer == issuer
    }
}
#[test]
fun 