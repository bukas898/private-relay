;; Privacy-First Encrypted Web3 Messaging Protocol
;; Focus: End-to-end encryption, key management, privacy preservation

;; Constants
(define-constant ERR_NOT_AUTHORIZED (err u100))
(define-constant ERR_KEY_NOT_FOUND (err u101))
(define-constant ERR_INVALID_SIGNATURE (err u102))
(define-constant ERR_MESSAGE_NOT_FOUND (err u103))
(define-constant ERR_DECRYPTION_FAILED (err u104))

;; Data Variables
(define-data-var next-message-id uint u1)
(define-data-var next-key-id uint u1)

;; Public key registry for encryption
(define-map user-public-keys
  { user: principal }
  {
    encryption-key: (buff 33), ;; Secp256k1 public key for encryption
    signing-key: (buff 33),    ;; Separate key for signatures
    key-version: uint,
    created-at: uint,
    last-updated: uint
  })

;; Encrypted message storage
(define-map encrypted-messages
  { id: uint }
  {
    sender: principal,
    recipient: principal,
    encrypted-content: (buff 256),     ;; Encrypted message content
    encrypted-key: (buff 64),          ;; Encrypted symmetric key
    nonce: (buff 24),                  ;; Encryption nonce
    signature: (buff 65),              ;; Message signature
    content-hash: (buff 32),           ;; Hash for integrity
    timestamp: uint,
    expires-at: (optional uint),
    ephemeral: bool                    ;; Auto-delete after reading
  })

;; Key exchange for secure communication
(define-map key-exchanges
  { id: uint }
  {
    initiator: principal,
    recipient: principal,
    ephemeral-key: (buff 33),          ;; One-time key for this exchange
    encrypted-session-key: (buff 64),  ;; Session key encrypted with recipient's key
    status: (string-ascii 10),         ;; "pending", "accepted", "rejected"
    created-at: uint,
    expires-at: uint
  })

;; Message metadata (non-encrypted info for filtering)
(define-map message-metadata
  { message-id: uint }
  {
    sender-hash: (buff 32),    ;; Hashed sender for privacy
    recipient-hash: (buff 32), ;; Hashed recipient
    size-category: (string-ascii 10), ;; "small", "medium", "large"
    priority: uint,
    read-receipt: bool,
    forwarded: bool
  })

;; Anonymous message boxes (steganographic)
(define-map anonymous-drops
  { drop-id: (buff 32) }  ;; Random drop ID
  {
    encrypted-payload: (buff 512),
    access-key-hash: (buff 32),  ;; Hash of access key
    created-at: uint,
    expires-at: uint,
    accessed: bool
  })

;; Zero-knowledge proof verification (placeholder for future ZK integration)
(define-map zk-proofs
  { proof-id: uint }
  {
    prover: principal,
    proof-type: (string-ascii 20),
    proof-data: (buff 128),
    verified: bool,
    created-at: uint
  })

;; Register encryption keys
(define-public (register-keys (encryption-key (buff 33)) 
                            (signing-key (buff 33)))
  (let ((user tx-sender))
    ;; Basic key validation (length check)
    (asserts! (is-eq (len encryption-key) u33) ERR_INVALID_SIGNATURE)
    (asserts! (is-eq (len signing-key) u33) ERR_INVALID_SIGNATURE)
    
    (map-set user-public-keys
      { user: user }
      {
        encryption-key: encryption-key,
        signing-key: signing-key,
        key-version: u1,
        created-at: stacks-block-height,
        last-updated: stacks-block-height
      })
    
    (print { 
      event: "keys-registered", 
      user: user,
      key-version: u1
    })
    
    (ok true)))

;; Send encrypted message
(define-public (send-encrypted (recipient principal)
                             (encrypted-content (buff 256))
                             (encrypted-key (buff 64))
                             (nonce (buff 24))
                             (signature (buff 65))
                             (content-hash (buff 32))
                             (expires-at (optional uint))
                             (ephemeral bool))
  (let ((sender tx-sender)
        (msg-id (get-next-message-id)))
    
    ;; Verify recipient has registered keys
    (asserts! (is-some (map-get? user-public-keys { user: recipient })) ERR_KEY_NOT_FOUND)
    
    ;; Store encrypted message
    (map-set encrypted-messages
      { id: msg-id }
      {
        sender: sender,
        recipient: recipient,
        encrypted-content: encrypted-content,
        encrypted-key: encrypted-key,
        nonce: nonce,
        signature: signature,
        content-hash: content-hash,
        timestamp: stacks-block-height,
        expires-at: expires-at,
        ephemeral: ephemeral
      })
    
    ;; Store privacy-preserving metadata
    (map-set message-metadata
      { message-id: msg-id }
      {
        sender-hash: (keccak256 (concat (unwrap-panic (to-consensus-buff? sender)) (unwrap-panic (to-consensus-buff? stacks-block-height)))),
        recipient-hash: (keccak256 (concat (unwrap-panic (to-consensus-buff? recipient)) (unwrap-panic (to-consensus-buff? stacks-block-height)))),
        size-category: (if (< (len encrypted-content) u100) "small" 
                         (if (< (len encrypted-content) u200) "medium" "large")),
        priority: u2,
        read-receipt: false,
        forwarded: false
      })
    
    ;; Emit minimal event (privacy-preserving)
    (print { 
      event: "encrypted-message",
      id: msg-id,
      timestamp: stacks-block-height,
      ephemeral: ephemeral
    })
    
    (ok msg-id)))

;; Initiate key exchange for perfect forward secrecy
(define-public (initiate-key-exchange (recipient principal)
                                    (ephemeral-key (buff 33))
                                    (encrypted-session-key (buff 64)))
  (let ((initiator tx-sender)
        (exchange-id (get-next-key-id))
        (expires (+ stacks-block-height u1008))) ;; ~1 week expiry
    
    ;; Verify recipient exists
    (asserts! (is-some (map-get? user-public-keys { user: recipient })) ERR_KEY_NOT_FOUND)
    
    (map-set key-exchanges
      { id: exchange-id }
      {
        initiator: initiator,
        recipient: recipient,
        ephemeral-key: ephemeral-key,
        encrypted-session-key: encrypted-session-key,
        status: "pending",
        created-at: stacks-block-height,
        expires-at: expires
      })
    
    (print {
      event: "key-exchange-initiated",
      exchange-id: exchange-id,
      initiator: initiator,
      recipient: recipient
    })
    
    (ok exchange-id)))

;; Accept key exchange
(define-public (accept-key-exchange (exchange-id uint))
  (match (map-get? key-exchanges { id: exchange-id })
    exchange (if (and (is-eq tx-sender (get recipient exchange))
                     (is-eq (get status exchange) "pending")
                     (< stacks-block-height (get expires-at exchange)))
               (begin
                 (map-set key-exchanges
                   { id: exchange-id }
                   (merge exchange { status: "accepted" }))
                 (print {
                   event: "key-exchange-accepted",
                   exchange-id: exchange-id
                 })
                 (ok true))
               ERR_NOT_AUTHORIZED)
    ERR_KEY_NOT_FOUND))

;; Anonymous message drop (for whistleblowing, etc.)
(define-public (create-anonymous-drop (drop-id (buff 32))
                                    (encrypted-payload (buff 512))
                                    (access-key-hash (buff 32))
                                    (ttl-blocks uint))
  (let ((expires (+ stacks-block-height ttl-blocks)))
    
    ;; Ensure drop ID is unique
    (asserts! (is-none (map-get? anonymous-drops { drop-id: drop-id })) ERR_NOT_AUTHORIZED)
    
    (map-set anonymous-drops
      { drop-id: drop-id }
      {
        encrypted-payload: encrypted-payload,
        access-key-hash: access-key-hash,
        created-at: stacks-block-height,
        expires-at: expires,
        accessed: false
      })
    
    ;; No identifying information in event
    (print {
      event: "anonymous-drop-created",
      expires-at: expires
    })
    
    (ok true)))

;; Access anonymous drop
(define-public (access-anonymous-drop (drop-id (buff 32)) (access-key (buff 32)))
  (match (map-get? anonymous-drops { drop-id: drop-id })
    drop (let ((key-hash (keccak256 access-key)))
           (asserts! (is-eq key-hash (get access-key-hash drop)) ERR_NOT_AUTHORIZED)
           (asserts! (< stacks-block-height (get expires-at drop)) ERR_NOT_AUTHORIZED)
           (asserts! (not (get accessed drop)) ERR_NOT_AUTHORIZED)
           
           ;; Mark as accessed
           (map-set anonymous-drops
             { drop-id: drop-id }
             (merge drop { accessed: true }))
           
           (print {
             event: "anonymous-drop-accessed",
             timestamp: stacks-block-height
           })
           
           (ok (get encrypted-payload drop)))
    ERR_MESSAGE_NOT_FOUND))

;; Self-destruct message after reading (for ephemeral messages)
(define-public (self-destruct-message (message-id uint))
  (match (map-get? encrypted-messages { id: message-id })
    msg (if (and (is-eq tx-sender (get recipient msg))
                (get ephemeral msg))
          (begin
            (map-delete encrypted-messages { id: message-id })
            (map-delete message-metadata { message-id: message-id })
            (print {
              event: "message-self-destructed",
              timestamp: stacks-block-height
            })
            (ok true))
          ERR_NOT_AUTHORIZED)
    ERR_MESSAGE_NOT_FOUND))

;; Update read receipt while preserving privacy
(define-public (mark-read-private (message-id uint))
  (match (map-get? message-metadata { message-id: message-id })
    metadata (match (map-get? encrypted-messages { id: message-id })
               msg (if (is-eq tx-sender (get recipient msg))
                     (begin
                       (map-set message-metadata
                         { message-id: message-id }
                         (merge metadata { read-receipt: true }))
                       (ok true))
                     ERR_NOT_AUTHORIZED)
               ERR_MESSAGE_NOT_FOUND)
    ERR_MESSAGE_NOT_FOUND))

;; Helper functions
(define-private (get-next-message-id)
  (let ((current-id (var-get next-message-id)))
    (var-set next-message-id (+ current-id u1))
    current-id))

(define-private (get-next-key-id)
  (let ((current-id (var-get next-key-id)))
    (var-set next-key-id (+ current-id u1))
    current-id))

;; Read-only functions (privacy-preserving)
(define-read-only (get-public-keys (user principal))
  (map-get? user-public-keys { user: user }))

(define-read-only (get-encrypted-message (message-id uint))
  ;; Only return to authorized parties
  (match (map-get? encrypted-messages { id: message-id })
    msg (if (or (is-eq tx-sender (get sender msg))
               (is-eq tx-sender (get recipient msg)))
          (some msg)
          none)
    none))

(define-read-only (get-message-metadata-anonymous (message-id uint))
  ;; Returns non-identifying metadata only
  (match (map-get? message-metadata { message-id: message-id })
    metadata (some {
      size-category: (get size-category metadata),
      priority: (get priority metadata),
      read-receipt: (get read-receipt metadata),
      forwarded: (get forwarded metadata)
    })
    none))

(define-read-only (get-key-exchange (exchange-id uint))
  (match (map-get? key-exchanges { id: exchange-id })
    exchange (if (or (is-eq tx-sender (get initiator exchange))
                    (is-eq tx-sender (get recipient exchange)))
               (some exchange)
               none)
    none))

(define-read-only (has-active-keys (user principal))
  (is-some (map-get? user-public-keys { user: user })))

;; Privacy-preserving message count (no user identification)
(define-read-only (get-total-encrypted-messages)
  (- (var-get next-message-id) u1))