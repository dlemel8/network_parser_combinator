use std::error::Error;

use network_parser_combinator::{tls, Protocol};

// TLS 1.3 session payloads
static CLIENT_START_OF_HANDSHAKE_PAYLOAD: &str = "16030100e9010000e503032635fafc16c49a3e997ef714c303806dc8dbf634a2005b0e0186521c4ad6f9df2023c3a84ca631f3a948d15d929c972e00dded0857f2a00fbadd56175c4e362b840024130113021303c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f0035000a01000078ff010001000017000000230000000d00140012040308040401050308050501080606010201000b00020100003300260024001d00200716eeca96799d784366f4455c066a046816ee00d2aec9ef84dd4358e6b6db35002d00020101002b000d0c03047f1c7f17030303020301000a00080006001d00170018";
static SERVER_HANDSHAKE_PAYLOAD: &str = "160303007a0200007603033f5e55c1cdb96b098828bf5d5d2cb490f35f9200ae1bf527005a24efdf9747592023c3a84ca631f3a948d15d929c972e00dded0857f2a00fbadd56175c4e362b84130100002e00330024001d002044ed3de867430475e6075915d0909a72557b730c815c015d23e58432922b9645002b0002030414030300010117030301c6b0da422f4bc587e12c65524b61d8da2a3b36608c60ff951a2e86dbf7881b5e19ed494ee387c89faa94818ed886b4ae53f41465265208c9d7d9efac747b43c0bd272726b46ff54b7074dbdccc39b91d5b6b5247a72018c3acae9c19a62d4cb3f0ecfd0a671c875adba2603ed9cfde21ed7187d305db395974ec473f910d48a87190883be0646f3e6cc19a0d54ba84c67a693b76deee70da15936a304836978c944aa0d4a510aa458a8c2cc8b32d60fc68f7c7e1908e5c8db511aed3e464c0844e7f0fe363bf406556808d86ebcc2fb1b95058b4ae720404b60003843ead150215778a7658bdb5b380aae208a49d148e337fe1b3cde31e22686fafe6b68923473a55ebf8e17fd3b79b060bbe03250a265e089b01ee67deda5441a5536b8c09a789a528d854853339123479b4d76e927ab7cf7a7d921931e3bde1c18a9420404c3dfaa35539dbd69a02a794e5a6261c139d9dd2801eb97ca2f24327a3e17b853bee06cfa952071cd47cce22edfc3f89c6c4404cc115c8d1ff527ccd8ff2fc6bc9d9222d3e15b54cbc52828eabc664aa45107d70dc41cf8f24b3dd506565e1a7c571a01e8d0819c128fa8c4a9c19e0dea3f28ad7bc2f1141f743a48bb0fe65ebc8090622228b5bf4";
static CLIENT_END_OF_HANDSHAKE_PAYLOAD: &str = "140303000101170303003592f6bc7755d670ae91832e2ff5ac6137191f82113c20584376c4d4431d65568403f3f5bf388ae95dd184c5c0d475a6fdb3b89f13a8";
static ENCRYPTED_APPLICATION_DATA: &str = "170303018da69a573677c53a37af0720d00c9bbbbc82f88489346f930df50b72639e8b5ff1ce9fd0bb41ae7b839cfa6a3d0d1512247b5e31374c2100dbb20aece514ed7a0a875434ade4dac96319c3ca5b9d8e161178b2666ec4cc9c1c5c5af2a2937053e317b36bf6284390416d1a0b7d4964f9d662c1f803b5b88059d0b86f5dddf6b1dd19fe9475b9dd81576456d5cc8095f6e8a7ee8055d82bd993307a8b100a32c2230e517a429cb1a2509af621f19095f82deacdd3bec0fc5d22c9ba3b87483d003bd88dd3ab6c958250325352075c6f3f18a1a6e4984a9c076c7e23e109389121e1d551c895a204d305f543ff64338e11d24bf080c2369ee38740148885dbd0d0aecf27cced45e6c757dc010718af4842d2f7bbe497734348889d3c6ef0185388b2210179fafea21bcb7260e6ececab9a61e4cf7585e4fceca2a1fb82a3f043f0aaf02ec5b02ab0546ddbc61cdc3516c829b2ac6d7e0ea2a13b321d14fb06bc7a8fb7002b90327415130b8de5c7242a361e20718340c22061bb403697029fccd481aea03be24ec9602e2641f81dba";

#[test]
fn tls_parser_client_start_of_handshake() -> Result<(), Box<dyn Error>> {
    let payload = hex::decode(CLIENT_START_OF_HANDSHAKE_PAYLOAD).expect("failed to decode payload");
    let protocol = network_parser_combinator::parse(payload.as_slice());
    assert_eq!(Protocol::Tls(vec![
        tls::Record {
            content_type: tls::ContentType::Handshake,
            version: "1.0".to_string(),
            data: tls::Data::HandshakeProtocol(tls::HandshakeProtocol::ClientHello(
                "1.2".to_string(),
                18,
                1,
                vec![
                    tls::Extension::RenegotiationInfo,
                    tls::Extension::ExtendedMasterSecret,
                    tls::Extension::SessionTicketTLS,
                    tls::Extension::SignatureAlgorithms,
                    tls::Extension::EcPointFormats,
                    tls::Extension::KeyShare,
                    tls::Extension::PskExchangeModes,
                    tls::Extension::SupportedVersions(vec![
                        "1.3".to_string(),
                        "1.3 (draft 28)".to_string(),
                        "1.3 (draft 23)".to_string(),
                        "1.2".to_string(),
                        "1.1".to_string(),
                        "1.0".to_string(),
                    ]),
                    tls::Extension::SupportedGroups,
                ],
            )),
        }
    ]), protocol);
    Ok(())
}

#[test]
fn tls_parser_server_handshake() -> Result<(), Box<dyn Error>> {
    let payload = hex::decode(SERVER_HANDSHAKE_PAYLOAD).expect("failed to decode payload");
    let protocol = network_parser_combinator::parse(payload.as_slice());
    assert_eq!(Protocol::Tls(vec![
        tls::Record {
            content_type: tls::ContentType::Handshake,
            version: "1.2".to_string(),
            data: tls::Data::HandshakeProtocol(tls::HandshakeProtocol::ServerHello(
                "1.2".to_string(),
                vec![
                    tls::Extension::KeyShare,
                    tls::Extension::SupportedVersions(vec!["1.3".to_string()]),
                ],
            )),
        },
        tls::Record {
            content_type: tls::ContentType::ChangeCipherSpec,
            version: "1.2".to_string(),
            data: tls::Data::ChangeCipherSpec,
        },
        tls::Record {
            content_type: tls::ContentType::ApplicationData,
            version: "1.2".to_string(),
            data: tls::Data::Encrypted(&[176, 218, 66, 47, 75, 197, 135, 225, 44, 101, 82, 75, 97, 216, 218, 42, 59, 54, 96, 140, 96, 255, 149, 26, 46, 134, 219, 247, 136, 27, 94, 25, 237, 73, 78, 227, 135, 200, 159, 170, 148, 129, 142, 216, 134, 180, 174, 83, 244, 20, 101, 38, 82, 8, 201, 215, 217, 239, 172, 116, 123, 67, 192, 189, 39, 39, 38, 180, 111, 245, 75, 112, 116, 219, 220, 204, 57, 185, 29, 91, 107, 82, 71, 167, 32, 24, 195, 172, 174, 156, 25, 166, 45, 76, 179, 240, 236, 253, 10, 103, 28, 135, 90, 219, 162, 96, 62, 217, 207, 222, 33, 237, 113, 135, 211, 5, 219, 57, 89, 116, 236, 71, 63, 145, 13, 72, 168, 113, 144, 136, 59, 224, 100, 111, 62, 108, 193, 154, 13, 84, 186, 132, 198, 122, 105, 59, 118, 222, 238, 112, 218, 21, 147, 106, 48, 72, 54, 151, 140, 148, 74, 160, 212, 165, 16, 170, 69, 138, 140, 44, 200, 179, 45, 96, 252, 104, 247, 199, 225, 144, 142, 92, 141, 181, 17, 174, 211, 228, 100, 192, 132, 78, 127, 15, 227, 99, 191, 64, 101, 86, 128, 141, 134, 235, 204, 47, 177, 185, 80, 88, 180, 174, 114, 4, 4, 182, 0, 3, 132, 62, 173, 21, 2, 21, 119, 138, 118, 88, 189, 181, 179, 128, 170, 226, 8, 164, 157, 20, 142, 51, 127, 225, 179, 205, 227, 30, 34, 104, 111, 175, 230, 182, 137, 35, 71, 58, 85, 235, 248, 225, 127, 211, 183, 155, 6, 11, 190, 3, 37, 10, 38, 94, 8, 155, 1, 238, 103, 222, 218, 84, 65, 165, 83, 107, 140, 9, 167, 137, 165, 40, 216, 84, 133, 51, 57, 18, 52, 121, 180, 215, 110, 146, 122, 183, 207, 122, 125, 146, 25, 49, 227, 189, 225, 193, 138, 148, 32, 64, 76, 61, 250, 163, 85, 57, 219, 214, 154, 2, 167, 148, 229, 166, 38, 28, 19, 157, 157, 210, 128, 30, 185, 124, 162, 242, 67, 39, 163, 225, 123, 133, 59, 238, 6, 207, 169, 82, 7, 28, 212, 124, 206, 34, 237, 252, 63, 137, 198, 196, 64, 76, 193, 21, 200, 209, 255, 82, 124, 205, 143, 242, 252, 107, 201, 217, 34, 45, 62, 21, 181, 76, 188, 82, 130, 142, 171, 198, 100, 170, 69, 16, 125, 112, 220, 65, 207, 143, 36, 179, 221, 80, 101, 101, 225, 167, 197, 113, 160, 30, 141, 8, 25, 193, 40, 250, 140, 74, 156, 25, 224, 222, 163, 242, 138, 215, 188, 47, 17, 65, 247, 67, 164, 139, 176, 254, 101, 235, 200, 9, 6, 34, 34, 139, 91, 244]),
        }
    ]), protocol);
    Ok(())
}

#[test]
fn tls_parser_client_end_of_handshake() -> Result<(), Box<dyn Error>> {
    let payload = hex::decode(CLIENT_END_OF_HANDSHAKE_PAYLOAD).expect("failed to decode payload");
    let protocol = network_parser_combinator::parse(payload.as_slice());
    assert_eq!(Protocol::Tls(vec![
        tls::Record {
            content_type: tls::ContentType::ChangeCipherSpec,
            version: "1.2".to_string(),
            data: tls::Data::ChangeCipherSpec,
        },
        tls::Record {
            content_type: tls::ContentType::ApplicationData,
            version: "1.2".to_string(),
            data: tls::Data::Encrypted(&[146, 246, 188, 119, 85, 214, 112, 174, 145, 131, 46, 47, 245, 172, 97, 55, 25, 31, 130, 17, 60, 32, 88, 67, 118, 196, 212, 67, 29, 101, 86, 132, 3, 243, 245, 191, 56, 138, 233, 93, 209, 132, 197, 192, 212, 117, 166, 253, 179, 184, 159, 19, 168]),
        }
    ]), protocol);
    Ok(())
}

#[test]
fn tls_parser_encrypted_application_data() -> Result<(), Box<dyn Error>> {
    let payload = hex::decode(ENCRYPTED_APPLICATION_DATA).expect("failed to decode payload");
    let protocol = network_parser_combinator::parse(payload.as_slice());
    assert_eq!(Protocol::Tls(vec![
        tls::Record {
            content_type: tls::ContentType::ApplicationData,
            version: "1.2".to_string(),
            data: tls::Data::Encrypted(&[166, 154, 87, 54, 119, 197, 58, 55, 175, 7, 32, 208, 12, 155, 187, 188, 130, 248, 132, 137, 52, 111, 147, 13, 245, 11, 114, 99, 158, 139, 95, 241, 206, 159, 208, 187, 65, 174, 123, 131, 156, 250, 106, 61, 13, 21, 18, 36, 123, 94, 49, 55, 76, 33, 0, 219, 178, 10, 236, 229, 20, 237, 122, 10, 135, 84, 52, 173, 228, 218, 201, 99, 25, 195, 202, 91, 157, 142, 22, 17, 120, 178, 102, 110, 196, 204, 156, 28, 92, 90, 242, 162, 147, 112, 83, 227, 23, 179, 107, 246, 40, 67, 144, 65, 109, 26, 11, 125, 73, 100, 249, 214, 98, 193, 248, 3, 181, 184, 128, 89, 208, 184, 111, 93, 221, 246, 177, 221, 25, 254, 148, 117, 185, 221, 129, 87, 100, 86, 213, 204, 128, 149, 246, 232, 167, 238, 128, 85, 216, 43, 217, 147, 48, 122, 139, 16, 10, 50, 194, 35, 14, 81, 122, 66, 156, 177, 162, 80, 154, 246, 33, 241, 144, 149, 248, 45, 234, 205, 211, 190, 192, 252, 93, 34, 201, 186, 59, 135, 72, 61, 0, 59, 216, 141, 211, 171, 108, 149, 130, 80, 50, 83, 82, 7, 92, 111, 63, 24, 161, 166, 228, 152, 74, 156, 7, 108, 126, 35, 225, 9, 56, 145, 33, 225, 213, 81, 200, 149, 162, 4, 211, 5, 245, 67, 255, 100, 51, 142, 17, 210, 75, 240, 128, 194, 54, 158, 227, 135, 64, 20, 136, 133, 219, 208, 208, 174, 207, 39, 204, 237, 69, 230, 199, 87, 220, 1, 7, 24, 175, 72, 66, 210, 247, 187, 228, 151, 115, 67, 72, 136, 157, 60, 110, 240, 24, 83, 136, 178, 33, 1, 121, 250, 254, 162, 27, 203, 114, 96, 230, 236, 236, 171, 154, 97, 228, 207, 117, 133, 228, 252, 236, 162, 161, 251, 130, 163, 240, 67, 240, 170, 240, 46, 197, 176, 42, 176, 84, 109, 219, 198, 28, 220, 53, 22, 200, 41, 178, 172, 109, 126, 14, 162, 161, 59, 50, 29, 20, 251, 6, 188, 122, 143, 183, 0, 43, 144, 50, 116, 21, 19, 11, 141, 229, 199, 36, 42, 54, 30, 32, 113, 131, 64, 194, 32, 97, 187, 64, 54, 151, 2, 159, 204, 212, 129, 174, 160, 59, 226, 78, 201, 96, 46, 38, 65, 248, 29, 186]),
        }
    ]), protocol);
    Ok(())
}
