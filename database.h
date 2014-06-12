int8_t database_write(uint8_t *id, uint8_t *name, uint8_t name_length, uint32_t src_ip);
uint8_t* database_find(uint8_t *name, uint8_t name_length);
void database_thread(void *args);
