#ifndef UTI_10_TOKENIZER_H
#define UTI_10_TOKENIZER_H

#include <stddef.h>

// Define token types for UTI-10
typedef enum {
    NOTE,
    REST,
    DURATION,
    ARTICULATION,
    TEMPO,
    DYNAMIC,
    BAR
} TokenType;

// Token structure
typedef struct {
    TokenType type;
    char value[50];
} Token;

// Function prototypes
int utf8_tokenize(const char *input, Token *tokens, size_t max_tokens);
void render_tokens(const Token *tokens, size_t token_count);

#endif // UTI_10_TOKENIZER_H
