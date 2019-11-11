# demystify_saml_sso
docs, notes, links and adventures about saml sso.
## Intro

To have a quick idea on how saml sso works, let's take a look at [this useful video](https://www.youtube.com/watch?v=S9BpeOmuEz4&t=661s)

![](https://github.com/kinderp/demystify_saml_sso/blob/master/images/basic_saml.jpg)

## Lab

We're gonna use this [project](https://github.com/OTA-Insight/djangosaml2idp/tree/master/example_setup) as test lab.

It gives us a trivial sp and idp implementations that we'll use for testing and studying saml sso.

See its [README](https://github.com/OTA-Insight/djangosaml2idp/blob/master/example_setup/README.rst) in order to run those two instances (idp,sp) in a docker env.

## Urls

* sp.urls
    ```python
    urlpatterns = [
        path('logout/', auth_views.LogoutView.as_view()),
        path('saml2/', include('djangosaml2.urls')),
        path('', views.IndexView.as_view()),
    ]
    ```
* djangosaml2.urls
    ```python
    urlpatterns = [
        url(r'^login/$', views.login, name='saml2_login'),
        url(r'^acs/$', views.assertion_consumer_service, name='saml2_acs'),
        url(r'^logout/$', views.logout, name='saml2_logout'),
        url(r'^ls/$', views.logout_service, name='saml2_ls'),
        url(r'^ls/post/$', views.logout_service_post, name='saml2_ls_post'),
        url(r'^metadata/$', views.metadata, name='saml2_metadata'),
    ]
    ```

* idp.urls
    ```python
    urlpatterns = [
        path('idp/', include('djangosaml2idp.urls', namespace='djangosaml2')),
        path('login/', auth_views.LoginView.as_view(template_name='idp/login.html'), name='login'),
        path('logout/', auth_views.LogoutView.as_view()),
        path('admin/', admin.site.urls),
        path('', views.IndexView.as_view()),
    ]
    ```
* djangosaml2idp.urls
    ```python
    urlpatterns = [
        path('sso/post', views.sso_entry, name="saml_login_post"),
        path('sso/redirect', views.sso_entry, name="saml_login_redirect"),
        path('sso/init', views.SSOInitView.as_view(), name="saml_idp_init"),
        path('login/process/', views.LoginProcessView.as_view(), name='saml_login_process'),
        path('login/process_multi_factor/', views.ProcessMultiFactorView.as_view(), name='saml_multi_factor'),
        path('metadata/', views.metadata, name='saml2_idp_metadata'),
    ]
    ```


sp instance uses [djangosaml2](https://github.com/knaperek/djangosaml2/) urls to provide sp functionalties

idp instnace uses [djangosaml2idp](https://github.com/OTA-Insight/djangosaml2idp) urls to provide idp functionalities

In plus, each instance has its own url. Below a summary.

Url | View | Description |
------------ | ------------- | -------------
`/` |  | ...
`idp/sso/post/` |  | sso saml entry point view, it accepts auth request (SamlRequest) and redirect that to `idp/login/process/` the SamlResponse performer view
`idp/sso/redirect/` |  | ...
`idp/sso/init/` |  | ...
`idp/login/process/` |  | it performs saml auth process, generating for an input SamlRequest a SamlResponse and redirecting the latter to the sp acs url `saml2/acs/`
`idp/login/process_multi_factor/` |  | ...
`idp/metadata/` |  | ...


Url | View | Description |
------------ | ------------- | -------------
`/` | views.IndexView | SP root page. If an user is not looged into idp (sso has not been performed yet), it shows a link to `saml2/login/` from where sp will instantiate an auth request towards idp. If an user is already logged into idp (sso already performed) it will show some user's info.
`saml2/login/` | views.login | This view initiates the SAML2 Authorization handshake. It will create a SAMLRequest and redirect these data to the _idp sso entry page_ `/idp/sso/post`, from there user will be redirected to idp login process page `idp/login/process/` where idp auth process will be performed (an auth SamlResponse will be created and redirected to sp acs `saml2/acs/`). If an user is not logged into idp when contacting `idp/login/process/` it will be before redirected to django idp login page `/login/?next=/idp/login/process/` and after that auth he will be redirected again to `idp/login/process/` and sso will continue (SamlResponse sent to sp acs `saml2/acs/`)
`saml2/acs/` | views.assertion_consumer_service | SAML Authorization Response endpoint. The IdP will send its response to this view (SamlResponse coming from `idp/login/process/`)
`saml2/logout/` | views.logout | ...
`saml2/ls/` | views.logout_service | ...
`saml2/lspost/` | views.logout_service_post | ...

# SP Initiated

1. download [sp initiated trace](https://github.com/kinderp/demystify_saml_sso/blob/master/traces/trace_sp_initiated.pcapng) 
2. open this trace file with [wireshark](https://www.wireshark.org/)
3. apply this visualization filter just to show only saml sso packs `http and (tcp.port eq 9000 or tcp.port eq 8000)`

You should see something like that

![](https://github.com/kinderp/demystify_saml_sso/blob/master/images/wireshark.png)

Just one note to follow correctly saml flow in wireshark and on this README:

* Each row has an unique id (first wireshark column: `No.` at the top left of the window). 
* So e.g. if `No.`=481 that row on the screen will be referred here as `#trace481`

## trace#481 GET http://localhost:8000/saml2/login/

* [link](https://github.com/knaperek/djangosaml2/blob/643969701d3b4257a8d64c5c577602ebaa61de70/djangosaml2/views.py#L85)

    ```python
    def login(request,
            config_loader_path=None,
            wayf_template='djangosaml2/wayf.html',
            authorization_error_template='djangosaml2/auth_error.html',
            post_binding_form_template='djangosaml2/post_binding_form.html'):

      """SAML Authorization Request initiator
      This view initiates the SAML2 Authorization handshake
      using the pysaml2 library to create the AuthnRequest.
      It uses the SAML 2.0 Http Redirect protocol binding.
      * post_binding_form_template - path to a template containing HTML form with
      hidden input elements, used to send the SAML message data when HTTP POST
      binding is being used. You can customize this template to include custom
      branding and/or text explaining the automatic redirection process. Please
      see the example template in
      templates/djangosaml2/example_post_binding_form.html
      If set to None or nonexistent template, default form from the saml2 library
      will be rendered.
      """
    ```
    
* html

    ```html
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8" />
      </head>
      <body onload="document.forms[0].submit()">
        <noscript>
          <p>
            <strong>Note:</strong>
            Since your browser does not support JavaScript,
            you must press the Continue button once to proceed.
          </p>
        </noscript>
        <form action="http://localhost:9000/idp/sso/post" method="post">
          <input type="hidden" name="SAMLRequest" value="PD94bWwgdmVyc2lvbj0iMS4wIj8+CjxuczA6QXV0aG5SZXF1ZXN0IHhtbG5zOm5zMD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiB4bWxuczpuczE9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iIHhtbG5zOm5zMj0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyIgQXNzZXJ0aW9uQ29uc3VtZXJTZXJ2aWNlVVJMPSJodHRwOi8vbG9jYWxob3N0OjgwMDAvc2FtbDIvYWNzLyIgRGVzdGluYXRpb249Imh0dHA6Ly9sb2NhbGhvc3Q6OTAwMC9pZHAvc3NvL3Bvc3QiIElEPSJpZC1CNk9yYXAwc0VlMExxNHZEeiIgSXNzdWVJbnN0YW50PSIyMDE5LTExLTA3VDA4OjExOjQxWiIgUHJvdG9jb2xCaW5kaW5nPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YmluZGluZ3M6SFRUUC1QT1NUIiBWZXJzaW9uPSIyLjAiPjxuczE6SXNzdWVyIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6ZW50aXR5Ij5odHRwOi8vbG9jYWxob3N0OjgwMDAvc2FtbDIvbWV0YWRhdGEvPC9uczE6SXNzdWVyPjxuczI6U2lnbmF0dXJlIElkPSJTaWduYXR1cmUxIj48bnMyOlNpZ25lZEluZm8+PG5zMjpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PG5zMjpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjcnNhLXNoYTEiLz48bnMyOlJlZmVyZW5jZSBVUkk9IiNpZC1CNk9yYXAwc0VlMExxNHZEeiI+PG5zMjpUcmFuc2Zvcm1zPjxuczI6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz48bnMyOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvbnMyOlRyYW5zZm9ybXM+PG5zMjpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjc2hhMSIvPjxuczI6RGlnZXN0VmFsdWU+NDNiSThQVlhvaTIvSVoxVUZsMmJOaFB5S3NNPTwvbnMyOkRpZ2VzdFZhbHVlPjwvbnMyOlJlZmVyZW5jZT48L25zMjpTaWduZWRJbmZvPjxuczI6U2lnbmF0dXJlVmFsdWU+TC92S3JSMVphakNXVGc0c2ZSbTNvcnVyY3VEQjNLTmFuekF2OXhwSFJEQ2U1ek9RR1NvZUFZcmJFUjY0UVVnUAozLy9YclpnamY5ZGxjakIrSHlGZVdMTjJwWnZBRGdXTUV2WVkxYUNCUG9panpqTFR1THFoaXJEdUpWT3FWRWhLCkNyRjZ3dk9PWlZydjdQSzlNTVRnejNrMUkzQnZPNDg1UWk2MTF6bTlFYStET2lUOEdkSG93bnVBZjZ6bGxZVGMKT0JJckl1RnowQUtLNXBPOUtmOXRuUVFpeW9OazllbnJyM2FsbDBRbXNyS2NtWGJ2aktYSU5QL3IwMlJVeXNnbgp2YUNIY2dOS3gyREdhVFdyalZzb25aeG9GSk1vRUx6c0Q3MUdSak0zeVExaFNETnhEd2NmTDNhVlNnVXJDVGd2CnNUbkFhMWdFUEtYdHdKeGdTTis4ZHc9PTwvbnMyOlNpZ25hdHVyZVZhbHVlPjxuczI6S2V5SW5mbz48bnMyOlg1MDlEYXRhPjxuczI6WDUwOUNlcnRpZmljYXRlPk1JSURDVENDQWZHZ0F3SUJBZ0lKQUw2S0JSRlpjdEtSTUEwR0NTcUdTSWIzRFFFQkN3VUFNQnN4R1RBWEJnTlZCQU1NRUhOd0xteHZZMkZzYUc5emRDNWpiMjB3SGhjTk1UZ3dPREE0TVRneE56UTFXaGNOTWpnd09EQTFNVGd4TnpRMVdqQWJNUmt3RndZRFZRUUREQkJ6Y0M1c2IyTmhiR2h2YzNRdVkyOXRNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQW5XdlBIckFYWjhTNVRyclB3UGs3NDRzUXFJaDh4OHRYK1BHdEpwWkpPaWRBVm5CNXZHblpaYTVydnU2RXMrTTE1Q0FEK2N6MUdBc0JlZ0F6NEZWUDEySTNhbm90Q3duYm5iMEJ2ZHJDRDh6VkJlTWZxOE1oV0ZMbTA5SG9BaDdTVFd5RGkwKzBCQWdDRlB5Q3ZmQnZOSzVqOU4wSHlKZU1MRG5qdTdQV0FBSHI3cmdldDVGTnc2Tld4ZmpsSmlvd1NQcHFWZlRTakpjS1RjQnl0dG5tTG44TVBzNU41WWhQWDJDcUZXbm4zbXpsL3M3WGMzQVFIN3hDSEdmUVg3MzgwNjB2a203MnVmUElLaTkrb25BQkhKWU14M3A1VEk5ai9PN2cwNllveXBCNGs4MzlvZENDeW94Y2ZzSndqS0dyWm52RUI1RW84WlFKYmQza2ZTTHU1UUlEQVFBQm8xQXdUakFkQmdOVkhRNEVGZ1FVRUMxbjNsYmw1VFpPOWdqeTRWZU91S3Z0cVRzd0h3WURWUjBqQkJnd0ZvQVVFQzFuM2xibDVUWk85Z2p5NFZlT3VLdnRxVHN3REFZRFZSMFRCQVV3QXdFQi96QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFLTlBaaFFBMzAyOC90R0Y1MVJXOHZCZUhCcnkyQXhTRjNaQ2dkWndzekZNVjZsczYvOVp3YllIRSt5TjJlaE5YVHhkT2ZiWkl5OTBWeTBVSE1mSmszc3lLUHhRZUFNNy8xdWRXazUzVWZYYndXdXlod1VTZERoMDJIOG9YT1JNY00yTU9qNUNsL3FjVzVYN2RiaEZrZ3pSZnlUQWVib25oZThDU2ZON3VYR2drek84ZnQ3bmRrMXVLMmhLTDVWV0gxZS9nVGVnRlltL0NNakIvQ3docisyMjZvejFianVsYlU0VkorUlVrcmxWNitwdUNjeUJoY3Y4WlIzZjZZQUdIenNVdDdSTmpMZXlFdXFxdUExUWJ3bWxrZmVWOU5PTzlhQnBiQTVTUWMrNDNDdW5RZTFyTHNXb0lwQ2NqU214WUgxcVZEN3RITGhJN3lCcVB2NVJRVUE9PTwvbnMyOlg1MDlDZXJ0aWZpY2F0ZT48L25zMjpYNTA5RGF0YT48L25zMjpLZXlJbmZvPjwvbnMyOlNpZ25hdHVyZT48bnMwOk5hbWVJRFBvbGljeSBBbGxvd0NyZWF0ZT0iZmFsc2UiIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6ZW1haWxBZGRyZXNzIi8+PC9uczA6QXV0aG5SZXF1ZXN0Pgo="/>
          <input type="hidden" name="RelayState" value="/"/>
          <noscript>
            <input type="submit" value="Continue"/>
          </noscript>
        </form>
      </body>
    </html>
    ```

## trace#498 POST http://localhost:8000/idp/sso/post

* [link](https://github.com/OTA-Insight/djangosaml2idp/blob/919f9b522a26a9300b5322658ff6869e41ef1b0c/djangosaml2idp/views.py#L41)

    ```python
    def sso_entry(request):
    """ Entrypoint view for SSO. 
    Gathers the parameters from the HTTP request, stores them in the session
    and redirects the requester to the login_process view.
    """
    ```
    
## trace#506 GET http://localhost:8000/idp/login/process/

* [link](https://github.com/OTA-Insight/djangosaml2idp/blob/919f9b522a26a9300b5322658ff6869e41ef1b0c/djangosaml2idp/views.py#L106)

  ```python
  class LoginProcessView(LoginRequiredMixin, IdPHandlerViewMixin, View):
    """ View which processes the actual SAML request and 
    returns a self-submitting form with the SAML response.
    The login_required decorator ensures the user authenticates 
    first on the IdP using 'normal' ways.
    """
    ...
    ...
        def get(self, request, *args, **kwargs):
            ...
            ...
            http_args = self.IDP.apply_binding(
            binding=resp_args['binding'],
            msg_str="%s" % authn_resp,
            destination=resp_args['destination'],
            relay_state=request.session['RelayState'],
            response=True)

            logger.debug('http args are: %s' % http_args)

            return self.render_response(request, processor, http_args)

  ```
  
  ```python
  def render_response(self, request, processor, http_args):
        """ Return either as redirect to MultiFactorView or as html with self-submitting form.
        """
        if processor.enable_multifactor(request.user):
            # Store http_args in session for after multi factor is complete
            request.session['saml_data'] = http_args['data']
            logger.debug("Redirecting to process_multi_factor")
            return HttpResponseRedirect(reverse('saml_multi_factor'))
        logger.debug("Performing SAML redirect")
        return HttpResponse(http_args['data'])
  ```
  
  (Pdb) resp_args
  ```python
    {
     'in_response_to': 'id-ZN3HmAzSlq06ZYNGA', 
     'sp_entity_id': 'http://localhost:8000/saml2/metadata/', 
     'name_id_policy':   <saml2.samlp.NameIDPolicy object at 0x7fdd4908d128>, 
     'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST', 
     'destination': 'http://localhost:8000/saml2/acs/'
     }
  ```
  
  (Pdb) http_args
  ```python
  'headers': [('Content-type', 'text/html')], 
  'data': '<!DOCTYPE html>
           <html>
                <head>
                    <meta charset="utf-8" />
                </head>
                <body onload="document.forms[0].submit()">
                    <noscript>
                        <p>
                        <strong>Note:</strong>
                            Since your browser does not support JavaScript,
                            you must press the Continue button once to proceed.
                        </p>
                    </noscript>
                    <form action="http://localhost:8000/saml2/acs/" method="post">
                        <input type="hidden" name="SAMLResponse" value="PD94bWwgdmVyc....."/>
                        <input type="hidden" name="RelayState" value="/"/>
                            <noscript>
                                <input type="submit" value="Continue"/>
                            </noscript>
                    </form>
               </body>
            </html>', 
    'url': 'http://localhost:8000/saml2/acs/', 'method': 'POST'}
  ```
## trace#656 POST http://localhost:8000/saml2/acs/

* [link](https://github.com/knaperek/djangosaml2/blob/643969701d3b4257a8d64c5c577602ebaa61de70/djangosaml2/views.py#L243)

    ```python
    def assertion_consumer_service(request,
                               config_loader_path=None,
                               attribute_mapping=None,
                               create_unknown_user=None):
    """SAML Authorization Response endpoint
    The IdP will send its response to this view, which
    will process it with pysaml2 help and log the user
    in using the custom Authorization backend
    djangosaml2.backends.Saml2Backend that should be
    enabled in the settings.py
    """
    
        ...
        ...
        logger.debug('Trying to authenticate the user. Session info: %s', session_info)
        user = auth.authenticate(request=request,
                                 session_info=session_info,
                                 attribute_mapping=attribute_mapping,
                                 create_unknown_user=create_unknown_user)
        if user is None:
            logger.warning("Could not authenticate user received in SAML Assertion. Session info: %s", session_info)
            raise PermissionDenied

        auth.login(request, user)
        _set_subject_id(request.session, session_info['name_id'])
        logger.debug("User %s authenticated via SSO.", user)

        logger.debug('Sending the post_authenticated signal')
        post_authenticated.send_robust(sender=user, session_info=session_info)

        # redirect the user to the view where he came from
        default_relay_state = get_custom_setting('ACS_DEFAULT_REDIRECT_URL',
                                                 settings.LOGIN_REDIRECT_URL)
        relay_state = request.POST.get('RelayState', default_relay_state)
        if not relay_state:
            logger.warning('The RelayState parameter exists but is empty')
            relay_state = default_relay_state
        if not is_safe_url_compat(url=relay_state, allowed_hosts={request.get_host()}):
            relay_state = settings.LOGIN_REDIRECT_URL
        logger.debug('Redirecting to the RelayState: %s', relay_state)
        return HttpResponseRedirect(relay_state)
    ```
  
  
  ## trace#666 POST http://localhost:8000/
  
* [link](https://github.com/OTA-Insight/djangosaml2idp/blob/919f9b522a26a9300b5322658ff6869e41ef1b0c/example_setup/sp/sp/views.py#L8)
    
    ```python
    class IndexView(TemplateView):
    template_name = "sp/index.html"

    def get_context_data(self, **kwargs):
        context = super(IndexView, self).get_context_data(**kwargs)
        context.update({
            "logout_url": settings.LOGOUT_URL,
            "login_url": settings.LOGIN_URL,
        })
        if self.request.user.is_authenticated:
            context.update({
                "user_attrs": sorted([(field.name, getattr(self.request.user, field.name)) for field in self.request.user._meta.get_fields() if field.concrete]),
            })
        return context
    ```


    ```html
    <!doctype html>
    <html lang="en">

    <head>
      <meta charset="utf-8">
      <meta http-equiv="x-ua-compatible" content="ie=edge">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>SP</title>
    </head>

    <body>
        <p>-- @ Service Provider --</p>
        {% if request.user.is_authenticated %}
            <p>LOGGED IN -  <a href={{ logout_url }}>LOGOUT</a></p>
            <ul>
            {% for k, v in user_attrs %}
                <li>{{k}}: {{v}}</li>
            {% endfor %}
            </ul>
        {% else %}
            <p>LOGGED OUT - <a href={{ login_url }}>LOGIN</a></p>
        {% endif %}

    </body>

    </html>
    ```

## trace#670 HTTP/1.1 200 OK
  
  ```html
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta http-equiv="x-ua-compatible" content="ie=edge">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>SP</title>
    </head>

    <body>
        <p>-- @ Service Provider --</p>
            <p>LOGGED IN -  <a href=/logout/>LOGOUT</a></p>
            <ul>
                <li>date_joined: Nov. 6, 2019, 3:38 p.m.</li>
                <li>email: a.caristia@gmail.com</li>
                <li>first_name: </li>
                <li>groups: auth.Group.None</li>
                <li>id: 1</li>
                <li>is_active: True</li>
                <li>is_staff: True</li>
                <li>is_superuser: True</li>
                <li>last_login: Nov. 7, 2019, 8:11 a.m.</li>
                <li>last_name: </li>
                <li>password: !CUp4QV3hrpVXqgNwFpifyogqeOgfqGdoz0FPCUr0</li>
                <li>user_permissions: auth.Permission.None</li> 
                <li>username: antonio</li>
            </ul>


    </body>

    </html>
```

## Sp auth backend

SP's ACS link `http://localhost:8000/saml2/acs/` accepts SamlResponse generated by idp and performs authentication on SP side using that info.

That route is managed by this [assertion_consumer_service](https://github.com/knaperek/djangosaml2/blob/643969701d3b4257a8d64c5c577602ebaa61de70/djangosaml2/views.py#L243) view.

It uses `NameID` field's value in [SampResponse](https://github.com/kinderp/demystify_saml_sso/blob/master/README.md#sampresponse) to autheticate the incoming request session on django.

Do exist some [settings](https://github.com/knaperek/djangosaml2#user-attributes) in djangosaml2 in order to customize auth behaviour. Basically it will use `NameID` to autheticate the request using `django.contrib.auth.models.User` model and you can customize the meaning of `NamedID`:

```
When such assertion (SamlResponse) is received on the Django side it is used to find a Django user and create a session for it. By default djangosaml2 will do a query on the User model with the USERNAME_FIELD attribute but you can change it to any other attribute of the User model. For example, you can do this lookup using the 'email' attribute. In order to do so you should set the following setting:

SAML_DJANGO_USER_MAIN_ATTRIBUTE = 'email'
```

```
SAML_DJANGO_USER_MAIN_ATTRIBUTE_LOOKUP = '__iexact'
```

```
SAML_USE_NAME_ID_AS_USERNAME = True
```

## SampResponse

```xml
<?xml version="1.0"?>
<ns0:Response
    xmlns:ns0="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:ns1="urn:oasis:names:tc:SAML:2.0:assertion"
    xmlns:ns2="http://www.w3.org/2000/09/xmldsig#"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Destination="http://localhost:8000/saml2/acs/" ID="id-tsVBetQdIFO64GTli" InResponseTo="id-B6Orap0sEe0Lq4vDz" IssueInstant="2019-11-07T08:11:49Z" Version="2.0">
    <ns1:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://localhost:9000/idp/metadata</ns1:Issuer>
    <ns2:Signature Id="Signature1">
        <ns2:SignedInfo>
            <ns2:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <ns2:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
            <ns2:Reference URI="#id-tsVBetQdIFO64GTli">
                <ns2:Transforms>
                    <ns2:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                    <ns2:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                </ns2:Transforms>
                <ns2:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                <ns2:DigestValue>gdqi7huMOdnfTnXrwImxXvMUDqM=</ns2:DigestValue>
            </ns2:Reference>
        </ns2:SignedInfo>
        <ns2:SignatureValue>Q4UAgDJ2LxWNlqE0rB8+s4Pfl9bY8LYXn1KyAjXh3PlIS7Ssd42rohBcIwV+TjIu
0M+FiXDYSLOhFnMl6QUnKaR7KIx1UPcfZuqUYn5avsTMbNU84BPtRXWm74yvTkF+
m/h/2nTEYSRVgiMB6WPkBbGVV+141Af1S6JrPlpkxUAJ8Jfn4f1lRtqHtfAqzt0J
4DQADl1AAYt7eDgQHss6+YFLIvNYKk25JjGW2q3fWYtxxJENBU+8pHwX7OvBKU+y
e1UjCMc8gAfhTsST8Kau5qRvBfK6QPqxPCBdonlUyDQZiRtUj9zJMshQjc1lUBvD
dA5CUJiP1AQs1zOKopydnA==</ns2:SignatureValue>
        <ns2:KeyInfo>
            <ns2:X509Data>
                <ns2:X509Certificate>MIIDCzCCAfOgAwIBAgIJALYDB+Awm3SNMA0GCSqGSIb3DQEBCwUAMBwxGjAYBgNVBAMMEWlkcC5sb2NhbGhvc3QuY29tMB4XDTE4MDgwODE4MTcxM1oXDTI4MDgwNTE4MTcxM1owHDEaMBgGA1UEAwwRaWRwLmxvY2FsaG9zdC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCyL++77fy/kHSy7b14Xx4a084sHBNBRRG4GcPS1PVp4Ssv4Y74RnZYXNTYO3Fm76UHfv6BAWVc6UQXoScYp/DpDml9GS22bnBS3JQPIIp3tFhElWRd9m+e/FkK29F9L8WZDNzbMMQUhwNd/K/k/L9ycjISbbWlcO4rqHptaprWoQmpl8yvWPYVCiSDoj494rmjdF2kRVaJvGvb9YLM1ziUMl4iJUc7tjybz2efrkkERNmWZRiMKp7wPpDf2VJ81GP7Gp15PIVnmUKw4v2R6fFJkociW1TEm0xJJxmV+SiwyyQ/9oVShOBYwoYYZZm0N4fIRKiVaZ1m9eRFFKHrX01ZAgMBAAGjUDBOMB0GA1UdDgQWBBR63/bbGWxzIdeHNSovHUsYaaTZ5jAfBgNVHSMEGDAWgBR63/bbGWxzIdeHNSovHUsYaaTZ5jAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCWV6VaNdXRu8OrmYAeZtHL6xwdGbVcih1URRJmjOnwjKhQGJnzLGqEM8ofxibLIXKMxFRho+v1+2C8n6uNbQsvce5xHcygucKSZ56wN8iRtCFqrSWTZRTTs8yMfQpjYHXc4SBUKfVX0mQeHcBzd5MiUHAgWo2BYF3beEngrDEzCxckxpLspZymTzOOIlqYJwRL8KOxtTTaqIgX5A2/JNjGnbmgoCY39XG0xmL1X5BEzoGBjvkt4Sl+L0n+cz2WSDrMOxlEpwWZ78hmz2zYRegJOwDP6Tiov87fy6kxtirBD4Elozenqks1AcKFELY8Pi5Rbzad2vwjVUMi1Xe2J3b6</ns2:X509Certificate>
            </ns2:X509Data>
        </ns2:KeyInfo>
    </ns2:Signature>
    <ns0:Status>
        <ns0:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </ns0:Status>
    <ns1:Assertion ID="id-hjELwsH60G08vYZrR" IssueInstant="2019-11-07T08:11:49Z" Version="2.0">
        <ns1:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://localhost:9000/idp/metadata</ns1:Issuer>
        <ns2:Signature Id="Signature2">
            <ns2:SignedInfo>
                <ns2:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ns2:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
                <ns2:Reference URI="#id-hjELwsH60G08vYZrR">
                    <ns2:Transforms>
                        <ns2:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                        <ns2:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    </ns2:Transforms>
                    <ns2:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                    <ns2:DigestValue>fBjGT2iA6abXnhVIza4g3pQrsrk=</ns2:DigestValue>
                </ns2:Reference>
            </ns2:SignedInfo>
            <ns2:SignatureValue>q+VOEcAV856MV79bFyxlunMX9fiXVREZfO3tN5jMSteRUxqrR4yqHjyZ5/Bb7SN+
q9bCeHGLO3I4EuFA+1T578m5ediBM+ZtcLcotRI6wtGLHdYIEjIUjEBYUZflZ9qZ
xpeys0eGbVISPYbdbHaGz+yRlt0ml9y94eG638tMzmS5WSgNbAEIfp2UCWj9htLG
qUusiEXkWOJxu6U8t1GC6h7KVGJ/UtMt8tkQMnwH1pdvyNZdlKDJnXBXPoDSkmGr
vjsc4eY2Kv5IWQK2lD37A5PTb5H1RHXy/N+egMfBvvKFBGjeXzoxjGhwgHjUqX/M
FtkEE9DNz0yqaMwDaFDFhQ==</ns2:SignatureValue>
            <ns2:KeyInfo>
                <ns2:X509Data>
                    <ns2:X509Certificate>MIIDCzCCAfOgAwIBAgIJALYDB+Awm3SNMA0GCSqGSIb3DQEBCwUAMBwxGjAYBgNVBAMMEWlkcC5sb2NhbGhvc3QuY29tMB4XDTE4MDgwODE4MTcxM1oXDTI4MDgwNTE4MTcxM1owHDEaMBgGA1UEAwwRaWRwLmxvY2FsaG9zdC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCyL++77fy/kHSy7b14Xx4a084sHBNBRRG4GcPS1PVp4Ssv4Y74RnZYXNTYO3Fm76UHfv6BAWVc6UQXoScYp/DpDml9GS22bnBS3JQPIIp3tFhElWRd9m+e/FkK29F9L8WZDNzbMMQUhwNd/K/k/L9ycjISbbWlcO4rqHptaprWoQmpl8yvWPYVCiSDoj494rmjdF2kRVaJvGvb9YLM1ziUMl4iJUc7tjybz2efrkkERNmWZRiMKp7wPpDf2VJ81GP7Gp15PIVnmUKw4v2R6fFJkociW1TEm0xJJxmV+SiwyyQ/9oVShOBYwoYYZZm0N4fIRKiVaZ1m9eRFFKHrX01ZAgMBAAGjUDBOMB0GA1UdDgQWBBR63/bbGWxzIdeHNSovHUsYaaTZ5jAfBgNVHSMEGDAWgBR63/bbGWxzIdeHNSovHUsYaaTZ5jAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCWV6VaNdXRu8OrmYAeZtHL6xwdGbVcih1URRJmjOnwjKhQGJnzLGqEM8ofxibLIXKMxFRho+v1+2C8n6uNbQsvce5xHcygucKSZ56wN8iRtCFqrSWTZRTTs8yMfQpjYHXc4SBUKfVX0mQeHcBzd5MiUHAgWo2BYF3beEngrDEzCxckxpLspZymTzOOIlqYJwRL8KOxtTTaqIgX5A2/JNjGnbmgoCY39XG0xmL1X5BEzoGBjvkt4Sl+L0n+cz2WSDrMOxlEpwWZ78hmz2zYRegJOwDP6Tiov87fy6kxtirBD4Elozenqks1AcKFELY8Pi5Rbzad2vwjVUMi1Xe2J3b6</ns2:X509Certificate>
                </ns2:X509Data>
            </ns2:KeyInfo>
        </ns2:Signature>
        <ns1:Subject>
            <ns1:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" SPNameQualifier="http://localhost:8000/saml2/metadata/">antonio</ns1:NameID>
            <ns1:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <ns1:SubjectConfirmationData InResponseTo="id-B6Orap0sEe0Lq4vDz" NotOnOrAfter="2019-11-07T09:11:49Z" Recipient="http://localhost:8000/saml2/acs/"/>
            </ns1:SubjectConfirmation>
        </ns1:Subject>
        <ns1:Conditions NotBefore="2019-11-07T08:11:49Z" NotOnOrAfter="2019-11-07T09:11:49Z">
            <ns1:AudienceRestriction>
                <ns1:Audience>http://localhost:8000/saml2/metadata/</ns1:Audience>
            </ns1:AudienceRestriction>
        </ns1:Conditions>
        <ns1:AuthnStatement AuthnInstant="2019-11-07T08:11:49Z" SessionIndex="id-HjES207DX4bJXLXM3">
            <ns1:AuthnContext>
                <ns1:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</ns1:AuthnContextClassRef>
            </ns1:AuthnContext>
        </ns1:AuthnStatement>
        <ns1:AttributeStatement>
            <ns1:Attribute FriendlyName="email" Name="urn:oid:1.2.840.113549.1.9.1.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                <ns1:AttributeValue
                    xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">a.caristia@gmail.com
                </ns1:AttributeValue>
            </ns1:Attribute>
            <ns1:Attribute Name="first_name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                <ns1:AttributeValue
                    xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string"/>
                </ns1:Attribute>
                <ns1:Attribute Name="last_name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                    <ns1:AttributeValue
                        xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string"/>
                    </ns1:Attribute>
                    <ns1:Attribute Name="is_staff" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                        <ns1:AttributeValue
                            xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:boolean">true
                        </ns1:AttributeValue>
                    </ns1:Attribute>
                    <ns1:Attribute Name="is_superuser" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                        <ns1:AttributeValue
                            xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:boolean">true
                        </ns1:AttributeValue>
                    </ns1:Attribute>
                </ns1:AttributeStatement>
            </ns1:Assertion>
        </ns0:Response>
```
