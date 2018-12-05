#include "fission.h"
#include <microhttpd.h>
#include <uv.h>
#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <string.h>

struct SERVER_DATA
{
    struct MHD_Daemon *mhd_daemon;
    uv_poll_t *poll_handle;
};

MHD_AccessHandlerCallback access_handler_cb;

MHD_RequestCompletedCallback request_completed_cb;

uv_poll_cb on_poll_cb;

void shutdown_handler(uv_signal_t *handle, int sig);

int main(int argc,
         char **argv)
{
    const union MHD_DaemonInfo *info;
    struct MHD_Daemon *d = NULL;
    uv_poll_t poll_handle;
    uv_signal_t sigint_handle, sigterm_handle;
    struct SERVER_DATA cd = {NULL, &poll_handle};
    unsigned short port = 8888;

    if (argc == 2)
    {
        port = atoi(argv[1]);
    }

    uv_signal_init(uv_default_loop(), &sigint_handle);
    uv_signal_init(uv_default_loop(), &sigterm_handle);

    uv_signal_start(&sigint_handle, shutdown_handler, SIGINT);
    uv_signal_start(&sigterm_handle, shutdown_handler, SIGTERM);

    d = MHD_start_daemon(MHD_USE_EPOLL_LINUX_ONLY | MHD_USE_DEBUG,
                         port,
                         NULL,
                         NULL,
                         access_handler_cb,
                         NULL,
                         MHD_OPTION_NOTIFY_COMPLETED, request_completed_cb, NULL,
                         MHD_OPTION_END);
    if (d == NULL)
        return 1;

    printf("daemon started listening on port %d.\n", atoi(argv[1]));

    cd.mhd_daemon = d;

    sigterm_handle.data = sigint_handle.data = poll_handle.data = &cd;

    info = MHD_get_daemon_info(d, MHD_DAEMON_INFO_EPOLL_FD_LINUX_ONLY);

    uv_poll_init(uv_default_loop(), &poll_handle, info->listen_fd);

    uv_poll_start(&poll_handle, UV_READABLE, on_poll_cb);

    return uv_run(uv_default_loop(), UV_RUN_DEFAULT);
}

const char *CODE_PATH = "/userfunc/user";
const char *DEFAULT_FUNC = "handler";

REQUEST_HANDLER user_function = NULL;

struct request_context
{
    char *post_data;
    int post_data_size;
};

static unsigned int specialize();

static unsigned int specialize_v2(const REQUEST *req, RESPONSE *res);

static REQUEST_HANDLER load_function(const char *file_name, const char *func_name);

static int access_handler(void *cls,
                          struct MHD_Connection *connection,
                          const char *url,
                          const char *method,
                          const char *version,
                          const char *upload_data,
                          size_t *upload_data_size,
                          void **ptr)
{
    static int request_id = 0;
    RESPONSE user_response = {NULL, 0};
    REQUEST user_request = {url, method, NULL, 0};
    struct request_context *request = NULL;
    struct MHD_Response *response;
    int ret;
    unsigned int status_code = MHD_HTTP_OK;

    request = *ptr;
    if (NULL == request)
    {
        request = calloc(1, sizeof(struct request_context));
        if (NULL == request)
        {
            fprintf(stderr, "calloc error: %s\n", strerror(errno));
            return MHD_NO;
        }
        *ptr = request;
        return MHD_YES;
    }

    if (*upload_data_size > 0)
    {
        request->post_data = realloc(request->post_data, *upload_data_size);
        if (NULL == request->post_data)
        {
            fprintf(stderr, "realloc error: %s\n", strerror(errno));
            return MHD_NO;
        }

        memcpy(request->post_data + request->post_data_size, upload_data, *upload_data_size);

        request->post_data_size += *upload_data_size;

        *upload_data_size = 0; // The number of bytes NOT processed.
        return MHD_YES;
    }

    user_request.body = request->post_data;
    user_request.body_size = request->post_data_size;

    if (strcmp("/v2/specialize", url) == 0 && strcmp("POST", method) == 0)
    {
        status_code = specialize_v2(&user_request, &user_response);
    }
    else if (strcmp("/specialize", url) == 0 && strcmp("POST", method) == 0)
    {
        status_code = specialize(&user_response);
    }
    else if (strcmp("/healthz", url) == 0 && strcmp("GET", method) == 0)
    {
        status_code = 200;
    }
    else
    {
        if (NULL != user_function)
        {
            status_code = user_function(&user_request, &user_response);
        }
        else
        {
            user_response.body = strdup("Generic container: no requests supported");
            user_response.body_size = strlen(user_response.body);
            status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    printf("Received request number %d on URL: %s\n", ++request_id, url);

    *ptr = NULL; /* clear context pointer */
    response = MHD_create_response_from_buffer(user_response.body_size,
                                               (void *)user_response.body,
                                               MHD_RESPMEM_MUST_FREE);
    ret = MHD_queue_response(connection,
                             status_code,
                             response);
    MHD_destroy_response(response);
    return ret;
}

MHD_AccessHandlerCallback access_handler_cb = access_handler;

static void on_poll(uv_poll_t *handle, int status, int events)
{
    if (status == 0 && events & UV_READABLE)
    {
        struct SERVER_DATA *cd = handle->data;
        MHD_run(cd->mhd_daemon);
    }
}

uv_poll_cb on_poll_cb = on_poll;

void shutdown_handler(uv_signal_t *handle, int sig)
{
    struct SERVER_DATA *cd = handle->data;
    printf("shutting down with signal %d.\n", sig);

    printf("stopping MHD socket poller.\n");
    uv_poll_stop(cd->poll_handle);

    printf("stopping MHD daemon.\n");
    MHD_stop_daemon(cd->mhd_daemon);
    printf("MHD socket closed.\n");

    printf("closing default loop.\n");
    uv_loop_close(uv_default_loop());

    printf("exiting\n");

    exit(0);
}

static void req_comp(void *cls,
                     struct MHD_Connection *connection,
                     void **con_cls,
                     enum MHD_RequestTerminationCode toe)
{
    struct request_context *request = *con_cls;

    if (NULL == request)
        return;

    free(request->post_data);
    free(request);
}

MHD_RequestCompletedCallback request_completed_cb = req_comp;

static REQUEST_HANDLER load_function(const char *file_name, const char *func_name)
{
    uv_lib_t *lib = NULL;
    int lib_status = UV_UNKNOWN;
    REQUEST_HANDLER func = NULL;
    clock_t start = 0;
    clock_t elapsed = 0;

    start = clock();

    lib = (uv_lib_t *)malloc(sizeof(uv_lib_t));
    lib_status = uv_dlopen(file_name, lib);
    if (0 == lib_status)
    {
        lib_status = uv_dlsym(lib, func_name, (void **)&func);
    }

    if (0 == lib_status)
    {
        uv_dlclose(lib);
        elapsed = clock() - start;
        printf("user code loaded in %ld sec %.3lf ms\n", elapsed / CLOCKS_PER_SEC,
               (double)(elapsed % CLOCKS_PER_SEC) / 1000);
    }
    else
    {
        func = NULL;
        fprintf(stderr, "user code load error: %s\n", uv_dlerror(lib));
    }

    free(lib);

    return func;
}

static unsigned int specialize(RESPONSE *res)
{
    if (user_function != NULL)
    {
        res->body = strdup("Not a generic container.");
        res->body_size = strlen(res->body);
        return MHD_HTTP_BAD_REQUEST;
    }

    user_function = load_function(CODE_PATH, DEFAULT_FUNC);

    if (user_function == NULL)
    {
        res->body = strdup("Failure to load user function.");
        res->body_size = strlen(res->body);
        return MHD_HTTP_INTERNAL_SERVER_ERROR;
    }

    // The body content is for debugging purposes only.
    res->body = strdup("Specialization received.");
    res->body_size = strlen(res->body);
    return MHD_HTTP_ACCEPTED;
}

static unsigned int specialize_v2(const REQUEST *req, RESPONSE *res)
{
    json_t *root;
    json_error_t error;
    json_t *file_path = NULL;
    json_t *handler = NULL;
    char *func_name = NULL;
    char *file_name = NULL;
    char *module_name = NULL;

    if (user_function != NULL)
    {
        res->body = strdup("Not a generic container.");
        res->body_size = strlen(res->body);
        return MHD_HTTP_BAD_REQUEST;
    }
    printf("specializing: %.*s\n", (int)req->body_size, req->body);

    root = json_loadb(req->body, req->body_size, 0, &error);
    if (!root)
    {
        fprintf(stderr, "json error: on line %d: %s\n", error.line, error.text);
        res->body = strdup(error.text);
        res->body_size = strlen(error.text);
        return MHD_HTTP_BAD_REQUEST;
    }

    if (!json_is_object(root))
    {
        char *err = "Request body is not an object.";
        fprintf(stderr, "json error: %s\n", err);
        res->body = strdup(err);
        res->body_size = strlen(err);
        json_decref(root);
        return MHD_HTTP_BAD_REQUEST;
    }

    file_path = json_object_get(root, "filepath");
    handler = json_object_get(root, "functionName");
    if (!json_is_string(file_path) || !json_is_string(handler))
    {
        char *err = "Request body is missing a required field.";
        fprintf(stderr, "json error: %s\n", err);
        res->body = strdup(err);
        res->body_size = strlen(err);
        json_decref(root);
        return MHD_HTTP_BAD_REQUEST;
    }

    module_name = strdup(json_string_value(handler));

    func_name = strchr(module_name, '.');
    if (func_name)
    {
        *func_name = '\0';
        func_name++;
    }

    asprintf(&file_name, "%s/%s", json_string_value(file_path), module_name);
    if (file_name == NULL)
    {
        fprintf(stderr, "failure to allocate memory for file_name: %s\n", strerror(errno));
        res->body = strdup("Failure to specialize user function.");
        res->body_size = strlen(res->body);
        free(module_name);
        return MHD_HTTP_INTERNAL_SERVER_ERROR;
    }

    user_function = load_function(file_name, (func_name ? func_name : DEFAULT_FUNC));

    free(module_name);
    free(file_name);

    json_decref(root);

    if (user_function == NULL)
    {
        res->body = strdup("Failure to load user function.");
        res->body_size = strlen(res->body);
        return MHD_HTTP_INTERNAL_SERVER_ERROR;
    }

    // The body content is for debugging purposes only.
    res->body = strdup("Specialization received.");
    res->body_size = strlen(res->body);
    return MHD_HTTP_ACCEPTED;
}