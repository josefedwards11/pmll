#include <stdio.h>
#include <string.h>
#include "UTI-10-tokenizer.h"

// Function to check if a byte is the start of a UTF-8 character
static int is_utf8_start_byte(unsigned char byte) {
    return (byte & 0xC0) != 0x80; // Start byte does not have the pattern 10xxxxxx
}

// Function to tokenize a UTF-8 string
int utf8_tokenize(const char *input, Token *tokens, size_t max_tokens) {
    const char *delimiters = " \t\n"; // Define delimiters (space, tab, newline)
    const char *start = input;
    const char *current = input;
    size_t token_count = 0;

    while (*current && token_count < max_tokens) {
        // Check if the current character is a delimiter
        if (strchr(delimiters, *current) != NULL) {
            // Save the token if it's valid
            if (current > start) {
                size_t length = current - start;
                if (length >= sizeof(tokens[token_count].value)) {
                    length = sizeof(tokens[token_count].value) - 1;
                }
                strncpy(tokens[token_count].value, start, length);
                tokens[token_count].value[length] = '\0';
                // Determine token type based on value (simplified example)
                tokens[token_count].type = NOTE; // Placeholder for actual logic
                token_count++;
            }
            // Move past the delimiter and reset the token start
            current++;
            start = current;
        } else {
            // Handle UTF-8 character traversal
            if (is_utf8_start_byte((unsigned char)*current)) {
                current++;
                while (*current && (*current & 0xC0) == 0x80) {
                    current++; // Continue traversing multi-byte UTF-8 character
                }
            } else {
                current++;
            }
        }
    }

    // Save the last token if there is one
    if (current > start && token_count < max_tokens) {
        size_t length = current - start;
        if (length >= sizeof(tokens[token_count].value)) {
            length = sizeof(tokens[token_count].value) - 1;
        }
        strncpy(tokens[token_count].value, start, length);
        tokens[token_count].value[length] = '\0';
        // Determine token type based on value (simplified example)
        tokens[token_count].type = NOTE; // Placeholder for actual logic
        token_count++;
    }

    return token_count;
}

// Function to render tokens (placeholder implementation)
void render_tokens(const Token *tokens, size_t token_count) {
    for (size_t i = 0; i < token_count; i++) {
        printf("Token %zu: Type=%d, Value=%s\n", i, tokens[i].type, tokens[i].value);
    }
}
