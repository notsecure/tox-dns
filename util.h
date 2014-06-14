/* convert public key to string
 *  notes: dest must be (32 * 2) bytes large, src must be 32 bytes large
 */
void key_to_string(uint8_t *dest, uint8_t *src);

/* convert tox id to string
 *  notes: dest must be (TOX_ID_SIZE * 2) bytes large, src must be TOX_ID_SIZE bytes large
 */
void id_to_string(uint8_t *dest, uint8_t *src);

/* convert string to tox id
 *  on success: returns 1
 *  on failure: returns 0
 *  notes: src must be (TOX_ID_SIZE * 2) bytes large, dest must be TOX_ID_SIZE bytes large, some data may be written to dest even on failure
 */
_Bool string_to_id(uint8_t *dest, uint8_t *src);

/* check if the tox id's checksum is correct
 *  correct: returns 1
 *  incorrect: returns 0
 */
_Bool validate_id(uint8_t *id);

