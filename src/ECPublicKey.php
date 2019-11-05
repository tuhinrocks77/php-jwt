<?php

namespace Firebase\JWT;

class ECPublicKey
{
    const ASN1_INTEGER = 0x02;
    const ASN1_BIT_STRING = 0x03;
    const ASN1_OBJECT_IDENTIFIER = 0x06;
    const ASN1_SEQUENCE = 0x10;
    const OID = '1.2.840.10045.2.1';

    private $data;

    private static $curves = [
        'P-256' => '1.2.840.10045.3.1.7', // Len: 64
        // 'P-384' => '1.3.132.0.34', // Len: 96 (not yet supported)
        // 'P-521' => '1.3.132.0.35', // Len: 132 (not supported)
    ];

    public function __construct(array $data)
    {
        if (isset($data['d'])) {
            // The key is actually a private key
            throw new \Exception('Key data must be for a public key');
        }

        if (empty($data['crv'])) {
            throw new \Exception('crv not set');
        }

        if (!isset(self::$curves[$data['crv']])) {
            throw new \Exception('Unrecognised or unsupported EC curve');
        }

        $this->data = $data;
    }

    public function toPEM()
    {
        $oid = self::$curves[$this->data['crv']];
        $pem =
            self::encodeDER(
                self::ASN1_SEQUENCE,
                self::encodeDER(
                    self::ASN1_SEQUENCE,
                    self::encodeDER(
                        self::ASN1_OBJECT_IDENTIFIER,
                        self::encodeOID(self::OID)
                    )
                    . self::encodeDER(
                        self::ASN1_OBJECT_IDENTIFIER,
                        self::encodeOID($oid)
                    )
                ) .
                self::encodeDER(
                    self::ASN1_BIT_STRING,
                    chr(0x00) . chr(0x04)
                    . JWT::urlsafeB64Decode($this->data['x'])
                    . JWT::urlsafeB64Decode($this->data['y'])
                )
            );

        return sprintf(
            "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n",
            wordwrap(base64_encode($pem), 64, "\n", true)
        );
    }

    /**
     * Convert an ECDSA signature to an ASN.1 DER sequence
     *
     * @param   string $sig The ECDSA signature to convert
     * @return  string The encoded DER object
     */
    public static function encodeSignature($sig)
    {
        // Separate the signature into r-value and s-value
        list($r, $s) = str_split($sig, (int) (strlen($sig) / 2));

        // Trim leading zeros
        $r = ltrim($r, "\x00");
        $s = ltrim($s, "\x00");

        // Convert r-value and s-value from unsigned big-endian integers to
        // signed two's complement
        if (ord($r[0]) > 0x7f) {
            $r = "\x00" . $r;
        }
        if (ord($s[0]) > 0x7f) {
            $s = "\x00" . $s;
        }

        return self::encodeDER(
            self::ASN1_SEQUENCE,
            self::encodeDER(self::ASN1_INTEGER, $r) .
            self::encodeDER(self::ASN1_INTEGER, $s)
        );
    }

    /**
     * Encodes a value into a DER object.
     *
     * @param   int     $type DER tag
     * @param   string  $value the value to encode
     * @return  string  the encoded object
     */
    private static function encodeDER($type, $value)
    {
        $tag_header = 0;
        if ($type === self::ASN1_SEQUENCE) {
            $tag_header |= 0x20;
        }

        // Type
        $der = chr($tag_header | $type);

        // Length
        $der .= chr(strlen($value));

        return $der . $value;
    }

    /**
     * Encodes a string into a DER-encoded OID.
     *
     * @param   string $oid the OID string
     * @return  string the binary DER-encoded OID
     */
    private static function encodeOID($oid)
    {
        $octets = explode('.', $oid);

        // Get the first octet
        $oid = chr(array_shift($octets) * 40 + array_shift($octets));

        // Iterate over subsequent octets
        foreach ($octets as $octet) {
            if ($octet == 0) {
                $oid .= chr(0x00);
                continue;
            }
            $bin = '';

            while ($octet) {
                $bin .= chr(0x80 | ($octet & 0x7f));
                $octet >>= 7;
            }
            $bin[0] = $bin[0] & chr(0x7f);

            // Convert to big endian if necessary
            if (pack('V', 65534) == pack('L', 65534)) {
                $oid .= strrev($bin);
            } else {
                $oid .= $bin;
            }
        }

        return $oid;
    }
}