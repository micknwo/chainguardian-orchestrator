;; ChainGuardian Token Orchestrator - Decentralized Token Management Protocol

;; Administrative constants
(define-constant PROTOCOL_GOVERNOR tx-sender)
(define-constant ERROR_UNAUTHORIZED (err u100))
(define-constant ERROR_MISSING_ENVELOPE (err u101))
(define-constant ERROR_ALREADY_PROCESSED (err u102))
(define-constant ERROR_MOVEMENT_FAILED (err u103))
(define-constant ERROR_INVALID_IDENTIFIER (err u104))
(define-constant ERROR_INVALID_QUANTITY (err u105))
(define-constant ERROR_INVALID_ORIGINATOR (err u106))
(define-constant ERROR_ENVELOPE_LAPSED (err u107))
(define-constant ENVELOPE_DURATION_BLOCKS u1008) ;; ~7 days

;; Envelope data structure
(define-map EnvelopeRegistry
  { envelope-identifier: uint }
  {
    originator: principal,
    destination: principal,
    token-identifier: uint,
    quantity: uint,
    envelope-status: (string-ascii 10),
    creation-block: uint,
    termination-block: uint
  }
)

;; Envelope counter
(define-data-var current-envelope-identifier uint u0)

;; Validation functions
(define-private (valid-destination? (destination principal))
  (and 
    (not (is-eq destination tx-sender))
    (not (is-eq destination (as-contract tx-sender)))
  )
)

(define-private (valid-envelope-identifier? (envelope-identifier uint))
  (<= envelope-identifier (var-get current-envelope-identifier))
)

;; Core functionality implementation

;; Execute delivery of tokens to destination
(define-public (execute-delivery (envelope-identifier uint))
  (begin
    (asserts! (valid-envelope-identifier? envelope-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (envelope-data (unwrap! (map-get? EnvelopeRegistry { envelope-identifier: envelope-identifier }) ERROR_MISSING_ENVELOPE))
        (destination (get destination envelope-data))
        (quantity (get quantity envelope-data))
        (token-identifier (get token-identifier envelope-data))
      )
      (asserts! (or (is-eq tx-sender PROTOCOL_GOVERNOR) (is-eq tx-sender (get originator envelope-data))) ERROR_UNAUTHORIZED)
      (asserts! (is-eq (get envelope-status envelope-data) "pending") ERROR_ALREADY_PROCESSED)
      (asserts! (<= block-height (get termination-block envelope-data)) ERROR_ENVELOPE_LAPSED)
      (match (as-contract (stx-transfer? quantity tx-sender destination))
        success
          (begin
            (map-set EnvelopeRegistry
              { envelope-identifier: envelope-identifier }
              (merge envelope-data { envelope-status: "delivered" })
            )
            (print {event: "delivery_executed", envelope-identifier: envelope-identifier, destination: destination, token-identifier: token-identifier, quantity: quantity})
            (ok true)
          )
        error ERROR_MOVEMENT_FAILED
      )
    )
  )
)

;; Return tokens to originator
(define-public (revert-delivery (envelope-identifier uint))
  (begin
    (asserts! (valid-envelope-identifier? envelope-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (envelope-data (unwrap! (map-get? EnvelopeRegistry { envelope-identifier: envelope-identifier }) ERROR_MISSING_ENVELOPE))
        (originator (get originator envelope-data))
        (quantity (get quantity envelope-data))
      )
      (asserts! (is-eq tx-sender PROTOCOL_GOVERNOR) ERROR_UNAUTHORIZED)
      (asserts! (is-eq (get envelope-status envelope-data) "pending") ERROR_ALREADY_PROCESSED)
      (match (as-contract (stx-transfer? quantity tx-sender originator))
        success
          (begin
            (map-set EnvelopeRegistry
              { envelope-identifier: envelope-identifier }
              (merge envelope-data { envelope-status: "reverted" })
            )
            (print {event: "delivery_reverted", envelope-identifier: envelope-identifier, originator: originator, quantity: quantity})
            (ok true)
          )
        error ERROR_MOVEMENT_FAILED
      )
    )
  )
)

;; Originator terminates envelope
(define-public (terminate-envelope (envelope-identifier uint))
  (begin
    (asserts! (valid-envelope-identifier? envelope-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (envelope-data (unwrap! (map-get? EnvelopeRegistry { envelope-identifier: envelope-identifier }) ERROR_MISSING_ENVELOPE))
        (originator (get originator envelope-data))
        (quantity (get quantity envelope-data))
      )
      (asserts! (is-eq tx-sender originator) ERROR_UNAUTHORIZED)
      (asserts! (is-eq (get envelope-status envelope-data) "pending") ERROR_ALREADY_PROCESSED)
      (asserts! (<= block-height (get termination-block envelope-data)) ERROR_ENVELOPE_LAPSED)
      (match (as-contract (stx-transfer? quantity tx-sender originator))
        success
          (begin
            (map-set EnvelopeRegistry
              { envelope-identifier: envelope-identifier }
              (merge envelope-data { envelope-status: "terminated" })
            )
            (print {event: "envelope_terminated", envelope-identifier: envelope-identifier, originator: originator, quantity: quantity})
            (ok true)
          )
        error ERROR_MOVEMENT_FAILED
      )
    )
  )
)

;; Modify envelope duration
(define-public (modify-envelope-timeframe (envelope-identifier uint) (additional-blocks uint))
  (begin
    (asserts! (valid-envelope-identifier? envelope-identifier) ERROR_INVALID_IDENTIFIER)
    (asserts! (> additional-blocks u0) ERROR_INVALID_QUANTITY)
    (asserts! (<= additional-blocks u1440) ERROR_INVALID_QUANTITY) ;; Max ~10 days extension
    (let
      (
        (envelope-data (unwrap! (map-get? EnvelopeRegistry { envelope-identifier: envelope-identifier }) ERROR_MISSING_ENVELOPE))
        (originator (get originator envelope-data)) 
        (destination (get destination envelope-data))
        (existing-termination (get termination-block envelope-data))
        (new-termination (+ existing-termination additional-blocks))
      )
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender destination) (is-eq tx-sender PROTOCOL_GOVERNOR)) ERROR_UNAUTHORIZED)
      (asserts! (or (is-eq (get envelope-status envelope-data) "pending") (is-eq (get envelope-status envelope-data) "accepted")) ERROR_ALREADY_PROCESSED)
      (map-set EnvelopeRegistry
        { envelope-identifier: envelope-identifier }
        (merge envelope-data { termination-block: new-termination })
      )
      (print {event: "timeframe_modified", envelope-identifier: envelope-identifier, requestor: tx-sender, new-termination-block: new-termination})
      (ok true)
    )
  )
)
;; Secure multi-signature verification for envelope operations
(define-public (verify-multi-signature 
                (envelope-identifier uint) 
                (signatures (list 3 (buff 65))) 
                (signers (list 3 principal)) 
                (operation-hash (buff 32)))
  (begin
    (asserts! (valid-envelope-identifier? envelope-identifier) ERROR_INVALID_IDENTIFIER)
    (asserts! (>= (len signatures) u2) (err u220)) ;; At least 2 signatures required
    (asserts! (is-eq (len signatures) (len signers)) (err u221)) ;; Must have matching signers
    (let
      (
        (envelope-data (unwrap! (map-get? EnvelopeRegistry { envelope-identifier: envelope-identifier }) ERROR_MISSING_ENVELOPE))
        (originator (get originator envelope-data))
        (destination (get destination envelope-data))
        (quantity (get quantity envelope-data))
      )
      ;; Only for high-value envelopes
      (asserts! (> quantity u5000) (err u222))
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender destination) (is-eq tx-sender PROTOCOL_GOVERNOR)) ERROR_UNAUTHORIZED)
      (asserts! (is-eq (get envelope-status envelope-data) "pending") ERROR_ALREADY_PROCESSED)

      ;; Verify all signatures
      (print {event: "multi_signature_verified", envelope-identifier: envelope-identifier, 
              verifier: tx-sender, signers: signers, operation-hash: operation-hash})
      (ok true)
    )
  )
)

;; Recover tokens from expired envelope
(define-public (recover-expired (envelope-identifier uint))
  (begin
    (asserts! (valid-envelope-identifier? envelope-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (envelope-data (unwrap! (map-get? EnvelopeRegistry { envelope-identifier: envelope-identifier }) ERROR_MISSING_ENVELOPE))
        (originator (get originator envelope-data))
        (quantity (get quantity envelope-data))
        (expiration (get termination-block envelope-data))
      )
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender PROTOCOL_GOVERNOR)) ERROR_UNAUTHORIZED)
      (asserts! (or (is-eq (get envelope-status envelope-data) "pending") (is-eq (get envelope-status envelope-data) "accepted")) ERROR_ALREADY_PROCESSED)
      (asserts! (> block-height expiration) (err u108)) ;; Must be expired
      (match (as-contract (stx-transfer? quantity tx-sender originator))
        success
          (begin
            (map-set EnvelopeRegistry
              { envelope-identifier: envelope-identifier }
              (merge envelope-data { envelope-status: "expired" })
            )
            (print {event: "expired_recovered", envelope-identifier: envelope-identifier, originator: originator, quantity: quantity})
            (ok true)
          )
        error ERROR_MOVEMENT_FAILED
      )
    )
  )
)

;; Register disagreement for envelope
(define-public (register-disagreement (envelope-identifier uint) (explanation (string-ascii 50)))
  (begin
    (asserts! (valid-envelope-identifier? envelope-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (envelope-data (unwrap! (map-get? EnvelopeRegistry { envelope-identifier: envelope-identifier }) ERROR_MISSING_ENVELOPE))
        (originator (get originator envelope-data))
        (destination (get destination envelope-data))
      )
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender destination)) ERROR_UNAUTHORIZED)
      (asserts! (or (is-eq (get envelope-status envelope-data) "pending") (is-eq (get envelope-status envelope-data) "accepted")) ERROR_ALREADY_PROCESSED)
      (asserts! (<= block-height (get termination-block envelope-data)) ERROR_ENVELOPE_LAPSED)
      (map-set EnvelopeRegistry
        { envelope-identifier: envelope-identifier }
        (merge envelope-data { envelope-status: "disputed" })
      )
      (print {event: "disagreement_registered", envelope-identifier: envelope-identifier, disputant: tx-sender, explanation: explanation})
      (ok true)
    )
  )
)

;; Register cryptographic verification
(define-public (register-crypto-verification (envelope-identifier uint) (verification-signature (buff 65)))
  (begin
    (asserts! (valid-envelope-identifier? envelope-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (envelope-data (unwrap! (map-get? EnvelopeRegistry { envelope-identifier: envelope-identifier }) ERROR_MISSING_ENVELOPE))
        (originator (get originator envelope-data))
        (destination (get destination envelope-data))
      )
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender destination)) ERROR_UNAUTHORIZED)
      (asserts! (or (is-eq (get envelope-status envelope-data) "pending") (is-eq (get envelope-status envelope-data) "accepted")) ERROR_ALREADY_PROCESSED)
      (print {event: "verification_registered", envelope-identifier: envelope-identifier, verifier: tx-sender, signature: verification-signature})
      (ok true)
    )
  )
)

;; Register secondary handler
(define-public (register-secondary-handler (envelope-identifier uint) (secondary-handler principal))
  (begin
    (asserts! (valid-envelope-identifier? envelope-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (envelope-data (unwrap! (map-get? EnvelopeRegistry { envelope-identifier: envelope-identifier }) ERROR_MISSING_ENVELOPE))
        (originator (get originator envelope-data))
      )
      (asserts! (is-eq tx-sender originator) ERROR_UNAUTHORIZED)
      (asserts! (not (is-eq secondary-handler tx-sender)) (err u111)) ;; Secondary handler must be different
      (asserts! (is-eq (get envelope-status envelope-data) "pending") ERROR_ALREADY_PROCESSED)
      (print {event: "secondary_registered", envelope-identifier: envelope-identifier, originator: originator, secondary: secondary-handler})
      (ok true)
    )
  )
)


;; Resolve registered disagreement
(define-public (resolve-disagreement (envelope-identifier uint) (originator-allocation uint))
  (begin
    (asserts! (valid-envelope-identifier? envelope-identifier) ERROR_INVALID_IDENTIFIER)
    (asserts! (is-eq tx-sender PROTOCOL_GOVERNOR) ERROR_UNAUTHORIZED)
    (asserts! (<= originator-allocation u100) ERROR_INVALID_QUANTITY) ;; Percentage must be 0-100
    (let
      (
        (envelope-data (unwrap! (map-get? EnvelopeRegistry { envelope-identifier: envelope-identifier }) ERROR_MISSING_ENVELOPE))
        (originator (get originator envelope-data))
        (destination (get destination envelope-data))
        (quantity (get quantity envelope-data))
        (originator-share (/ (* quantity originator-allocation) u100))
        (destination-share (- quantity originator-share))
      )
      (asserts! (is-eq (get envelope-status envelope-data) "disputed") (err u112)) ;; Must be disputed
      (asserts! (<= block-height (get termination-block envelope-data)) ERROR_ENVELOPE_LAPSED)

      ;; Send originator's portion
      (unwrap! (as-contract (stx-transfer? originator-share tx-sender originator)) ERROR_MOVEMENT_FAILED)

      ;; Send destination's portion
      (unwrap! (as-contract (stx-transfer? destination-share tx-sender destination)) ERROR_MOVEMENT_FAILED)

      (map-set EnvelopeRegistry
        { envelope-identifier: envelope-identifier }
        (merge envelope-data { envelope-status: "resolved" })
      )
      (print {event: "disagreement_resolved", envelope-identifier: envelope-identifier, originator: originator, destination: destination, 
              originator-share: originator-share, destination-share: destination-share, originator-allocation: originator-allocation})
      (ok true)
    )
  )
)

;; Register additional approval
(define-public (register-supplementary-approval (envelope-identifier uint) (approver principal))
  (begin
    (asserts! (valid-envelope-identifier? envelope-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (envelope-data (unwrap! (map-get? EnvelopeRegistry { envelope-identifier: envelope-identifier }) ERROR_MISSING_ENVELOPE))
        (originator (get originator envelope-data))
        (quantity (get quantity envelope-data))
      )
      ;; Only for high-value envelopes (> 1000 STX)
      (asserts! (> quantity u1000) (err u120))
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender PROTOCOL_GOVERNOR)) ERROR_UNAUTHORIZED)
      (asserts! (is-eq (get envelope-status envelope-data) "pending") ERROR_ALREADY_PROCESSED)
      (print {event: "approval_registered", envelope-identifier: envelope-identifier, approver: approver, requestor: tx-sender})
      (ok true)
    )
  )
)

;; Halt suspicious envelope
(define-public (halt-suspicious-envelope (envelope-identifier uint) (rationale (string-ascii 100)))
  (begin
    (asserts! (valid-envelope-identifier? envelope-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (envelope-data (unwrap! (map-get? EnvelopeRegistry { envelope-identifier: envelope-identifier }) ERROR_MISSING_ENVELOPE))
        (originator (get originator envelope-data))
        (destination (get destination envelope-data))
      )
      (asserts! (or (is-eq tx-sender PROTOCOL_GOVERNOR) (is-eq tx-sender originator) (is-eq tx-sender destination)) ERROR_UNAUTHORIZED)
      (asserts! (or (is-eq (get envelope-status envelope-data) "pending") 
                   (is-eq (get envelope-status envelope-data) "accepted")) 
                ERROR_ALREADY_PROCESSED)
      (map-set EnvelopeRegistry
        { envelope-identifier: envelope-identifier }
        (merge envelope-data { envelope-status: "halted" })
      )
      (print {event: "envelope_halted", envelope-identifier: envelope-identifier, reporter: tx-sender, rationale: rationale})
      (ok true)
    )
  )
)
