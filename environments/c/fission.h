#ifndef _FISSION_H_
#define _FISSION_H_

typedef struct request
{
    const char *url;
    const char *method;
    const char *body;
    unsigned int body_size;
} REQUEST;

typedef struct response
{
    char *body;
    unsigned int body_size;
} RESPONSE;

typedef unsigned int (*REQUEST_HANDLER)(
    const REQUEST *req,
    RESPONSE *res);

#endif