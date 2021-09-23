# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

import functools
import logging

import json

import werkzeug.urls
import werkzeug.utils
from werkzeug.exceptions import BadRequest

from odoo import api, http, SUPERUSER_ID, _
from odoo.exceptions import AccessDenied
from odoo.http import request
from odoo import registry as registry_get

from odoo.addons.auth_signup.controllers.main import AuthSignupHome as Home
from odoo.addons.web.controllers.main import db_monodb, ensure_db, set_cookie_and_redirect, login_and_redirect

from lxml import etree
import base64


import requests
from datetime import datetime

_logger = logging.getLogger(__name__)

#----------------------------------------------------------
# helpers
#----------------------------------------------------------
def fragment_to_query_string(func):
    #_logger.info("1626897301")
    
    @functools.wraps(func)
    def wrapper(self, *a, **kw):
        #_logger.info("1626897302 INICIO wrapper")
        kw.pop('debug', False)
        if not kw:
            return """<html><head><script>
                var l = window.location;
                var q = l.hash.substring(1);
                var r = l.pathname + l.search;
                if(q.length !== 0) {
                    var s = l.search ? (l.search === '?' ? '' : '&') : '?';
                    r = l.pathname + l.search + s + q;
                }
                if (r == l.pathname) {
                    r = '/';
                }
                window.location = r;
            </script></head><body></body></html>"""
        
        #_logger.info("1626897302a FIN wrapper1")
        return func(self, *a, **kw)
    #_logger.info("1626897302b FIN wrapper2")
    return wrapper


#----------------------------------------------------------
# SAML Controller
#----------------------------------------------------------
class SamlLogin(Home):

    def list_saml_providers(self):
        _logger.info("62=== LIST SAML PROVIDERS INICIO")
        
        try:
            saml_providers = request.env['auth.saml.provider'].sudo().search_read([('enabled', '=', True)])
        except Exception:
            saml_providers = []
        for saml_provider in saml_providers:
            return_url = request.httprequest.url_root + 'auth_saml/acs'
            state = self.get_state(saml_provider)
            _logger.info("79==== State: %s", state)
            params = dict(
                id = saml_provider['id'],
                name = saml_provider['name'],
            )
            saml_provider['auth_link'] = "%s?%s" % (saml_provider['auth_endpoint'], werkzeug.urls.url_encode(params))
        
        _logger.info("62=== LIST SAML PROVIDERS FIN")
        return saml_providers

    def get_state(self, saml_provider):
        redirect = request.params.get('redirect') or 'web'

        if not redirect.startswith(('//', 'http://', 'https://')):
            redirect = '%s%s' % (request.httprequest.url_root, redirect[1:] if redirect[0] == '/' else redirect)
        state = dict(
            d=request.session.db,
            p=saml_provider['id'],
            r=werkzeug.urls.url_quote_plus(redirect),
        )
        token = request.params.get('token')
        
        if token:
            state['t'] = token
            
        return state
    
    @http.route()
    def web_login(self, *args, **kw):
        _logger.info("96=== WEB_LOGIN INICIO")
        
        ensure_db()
        
        if request.httprequest.method == 'GET' and request.session.uid and request.params.get('redirect'):
            return http.redirect_with_hash(request.params.get('redirect'))
        
        saml_providers = self.list_saml_providers()

        response = super(SamlLogin, self).web_login(*args, **kw)

        if response.is_qweb:
            error = request.params.get('saml_error') 
            if error == '1':
                error = _("Sign up is not allowed on this database.")
            elif error == '2':
                error = _("Access Denied")
            elif error == '3':
                error = _("You do not have access to this database or your invitation has expired. Please ask for an invitation and be sure to follow the link in your invitation email.")
            else:
                error = None

            response.qcontext['saml_providers'] = saml_providers
            if error:
                response.qcontext['error'] = error

        return response
    
    
    
    def get_auth_signup_qcontext(self):
        _logger.info("1626897306 INICIO get_auth_signup_qcontext")
        result = super(SamlLogin, self).get_auth_signup_qcontext()
        result["saml_providers"] = self.list_saml_providers()
        _logger.info("1626897306 FIN get_auth_signup_qcontext result %s", result )
        return result
    

    
class SamlController(http.Controller):

    @http.route('/web/auth_saml/acs', type='http', auth='none', csrf=False)  #OJO EL CSRF XXXXXXX
    @fragment_to_query_string
    def acs(self, **kw):
        
        if http.request.httprequest.method == 'POST':

            _logger.info("152====DEB KW: %s", kw )
            '''
            _logger.info("150 BUSCANDO media-dev httprequest: %s", url_headers.environ )
            _logger.info("142 BUSCANDO media-dev %s", dir( http.request ) )
            _logger.info("143 BUSCANDO media-dev auth_method %s", http.request.auth_method )
            _logger.info("144 BUSCANDO media-dev context %s", http.request.context )
            _logger.info("145 BUSCANDO media-dev %s", http.request.cr )
            _logger.info("146 BUSCANDO media-dev %s", http.request.csrf_token )
            _logger.info("147 BUSCANDO media-dev db %s", http.request.db )
            _logger.info("148 BUSCANDO media-dev %s", http.request.endpoint )
            _logger.info("149 BUSCANDO media-dev %s", http.request.env )
            _logger.info("150 BUSCANDO media-dev httprequest: %s", http.request.httprequest )
            _logger.info("151 BUSCANDO media-dev httpresponse %s", http.request.httpresponse )
            _logger.info("152 BUSCANDO media-dev params %s", http.request.params )
            _logger.info("153 BUSCANDO media-dev %s", http.request.registry )
            _logger.info("154 BUSCANDO media-dev %s", http.request.registry_cr )
            _logger.info("155 BUSCANDO media-dev session: %s", http.request.session )
            _logger.info("156 BUSCANDO media-dev uid: %s", http.request.uid )

            _logger.info("158 BUSCANDO media-dev: %s", dir(request.httprequest) )
            _logger.info("159 BUSCANDO media-dev: %s", request.httprequest.url_root )
            _logger.info("160 BUSCANDO media-dev httprequest: %s", http.request.httprequest.headers )
            '''
            '''
            url11 = "https://identity.lastpass.com/SAML/SSOService/05fa5c26-9032-48c3-a526-0718b8013e47"
            name1 = kw.get('name')
            _logger.info("177===name1 : %s", name1)
            STOP178
            if kw['name'] == "Lastpass":
                headers1 = {'Content-Type': 'application/json'}
                r = requests.post(
                    url11,
                    headers = headers1,
                    data = kw,
                )
                r.status_code
                _logger.info("164===== TEXT: %s", r.status_code )
                _logger.info("164===== TEXT: %s", r.text )
                
                
                STOP155
            '''
            

            saml_response_xml = base64.b64decode( kw['SAMLResponse'] ).decode()
            
            saml_data = self.get_saml_data( saml_response_xml )
            if not saml_data:
                STOP168_DEVOLVER_A_WEB_LOGIN_U_OTRO

            kw['SAMLResponse'] = saml_response_xml
            kw['saml_issuer'] = saml_data['saml_issuer']
            kw['saml_name_id'] = saml_data['saml_name_id']
            kw['saml_name_id_format'] = saml_data['saml_name_id_format']
            kw['access_token'] = saml_data['saml_session_index']
            kw['scope'] = 'userinfo'
            kw['expires_in'] = '1000' #CALCULAR ESTE VALOR XXXXX !!!
            kw['token_type'] = 'Bearer'
            kw['state'] = {
                'a': None,
                'd': http.request.db,
                'm': None,
                'r': request.httprequest.url_root + "web" #XXXXXX
            }
            
            if kw.get('state'):
                dbname = kw.get('state').get('d')
            else:
                dbname = False
            
            if not http.db_filter([dbname]):
                return BadRequest()
            
            context = {}
            
            registry = registry_get(dbname)
            with registry.cursor() as cr:
                env = api.Environment(cr, SUPERUSER_ID, context)
                saml_provider_id = env['auth.saml.provider'].sudo().get_provider_id( saml_data['saml_issuer'] ),
                cr.commit()
            
            kw['state']['p'] = saml_provider_id[0].id
            
            _logger.info("180 cont main POST self: %s, kw: %s", self, kw)
            
            state = kw['state']

            with registry.cursor() as cr:

                try:
                    
                    env = api.Environment(cr, SUPERUSER_ID, context)
                    
                    saml_provider = kw['state']['p']
                    credentials = env['res.users'].sudo().auth_saml(saml_provider, kw)
                    
                    cr.commit()

                    action = state.get('a')
                    menu = state.get('m')
                    redirect = werkzeug.urls.url_unquote_plus(state['r']) if state.get('r') else False

                    url = '/web'

                    if redirect:
                        url = redirect
                    elif action:
                        url = '/web#action=%s' % action
                    elif menu:
                        url = '/web#menu_id=%s' % menu
                    
                    
                    resp = login_and_redirect(*credentials, redirect_url=url)

                    if werkzeug.urls.url_parse(resp.location).path == '/web' and not request.env.user.has_group('base.group_user'):
                        resp.location = '/'
                    
                    return resp

                except AttributeError:
                    # saml_signup is not installed
                    _logger.error("saml_signup not installed on database %s: saml sign up cancelled." % (dbname,))
                    url = "/web/login?saml_error=1"
                except AccessDenied:
                    # SAML credentials not valid, user could be on a temporary session
                    _logger.info('SAML: access denied, redirect to main page in case a valid session exists, without setting cookies')
                    url = "/web/login?saml_error=3"

                    redirect = werkzeug.utils.redirect(url, 303)
                    redirect.autocorrect_location_header = False
                    return redirect
                except Exception as e:
                    # signup error
                    _logger.exception("SAML: %s" % str(e))
                    url = "/web/login?saml_error=2"

            output = set_cookie_and_redirect(url)

            saml_access_token = kw['access_token']
            credentials = request.env['res.users'].sudo()._check_credentials(saml_access_token, env)
            return output
        
        if http.request.httprequest.method == 'GET':
            
            
            #Construir el SamlRequest
            get_authnrequest = self.get_authnrequest(kw)
            
            return get_authnrequest
            
            if get_authnrequest.get('error'):
                return get_authnrequest.get('error')
            
            saml_form = get_authnrequest['saml_form']
            _logger.info("\n\n277 SAML FORM: %s", saml_form)


            return saml_form

            
            #Post al IDP
            
            #Obtener el FORM
            
            #Redireccionar al usuario al FORM
            
            #state = json.loads(kw['state'])
            _logger.info("266=== State: %s", kw)
            kw['state'] = {
                'd': http.request.db,
                'p': kw['id']
            }
            state = kw['state']

            dbname = state['d']
            _logger.info("266=== State: %s", kw)
            STOP275
            if not http.db_filter([dbname]):
                return BadRequest()
            provider = state['p']
            context = state.get('c', {})
            registry = registry_get(dbname)
            with registry.cursor() as cr:
                try:
                    env = api.Environment(cr, SUPERUSER_ID, context)
                    credentials = env['res.users'].sudo().auth_saml(saml_provider, kw)
                    cr.commit()
                    action = state.get('a')
                    menu = state.get('m')
                    redirect = werkzeug.urls.url_unquote_plus(state['r']) if state.get('r') else False
                    url = '/web'
                    if redirect:
                        url = redirect
                    elif action:
                        url = '/web#action=%s' % action
                    elif menu:
                        url = '/web#menu_id=%s' % menu
                    resp = login_and_redirect(*credentials, redirect_url=url)

                    if werkzeug.urls.url_parse(resp.location).path == '/web' and not request.env.user.has_group('base.group_user'):
                        resp.location = '/'
                    return resp
                except AttributeError:
                    # saml_signup is not installed
                    _logger.error("saml_signup not installed on database %s: oauth sign up cancelled." % (dbname,))
                    url = "/web/login?saml_error=1"
                except AccessDenied:
                    # saml credentials not valid, user could be on a temporary session
                    _logger.info('Saml2: access denied, redirect to main page in case a valid session exists, without setting cookies')
                    url = "/web/login?saml_error=3"
                    redirect = werkzeug.utils.redirect(url, 303)
                    redirect.autocorrect_location_header = False
                    return redirect
                except Exception as e:
                    # signup error
                    _logger.exception("Saml2: %s" % str(e))
                    url = "/web/login?saml_error=2"

            output = set_cookie_and_redirect(url)
            _logger.info("1626897307 FIN signin %s", output)
            #return set_cookie_and_redirect(url)
            return output
    

    def get_saml_data(self, saml_response_xml):
        
        is_saml_secure = self.check_saml_security()
        if not is_saml_secure:
            return False
        
        nss = { 'saml': "urn:oasis:names:tc:SAML:2.0:assertion",
                'samlp': "urn:oasis:names:tc:SAML:2.0:protocol"
              }
        
        root = etree.fromstring( saml_response_xml )
        
        saml_issuer_xml = root.findall(".//saml:Issuer", nss)
        if len( saml_issuer_xml ) > 0:
            saml_issuer = saml_issuer_xml[0].text
        else:
            saml_issuer = False
            
        saml_name_id_xml = root.findall(".//saml:NameID", nss)
        if len( saml_name_id_xml ) > 0:
            saml_name_id = saml_name_id_xml[0].text
            saml_name_id_format = saml_name_id_xml[0].get('Format')
        else:
            saml_issuer_id = False
        
        saml_authn_statement_xml = root.findall(".//saml:AuthnStatement", nss)
        if len( saml_authn_statement_xml ) > 0:
            saml_session_index = saml_authn_statement_xml[0].get('SessionIndex')
            saml_authn_instant = saml_authn_statement_xml[0].get('AuthnInstant')
            saml_session_notonor_after = saml_authn_statement_xml[0].get('SessionNotOnOrAfter')
        
        return  {   'saml_issuer' : saml_issuer,
                    'saml_name_id': saml_name_id,
                    'saml_name_id_format': saml_name_id_format,
                    'saml_session_index': saml_session_index,
                    'saml_authn_instant': saml_authn_instant,
                    'saml_session_notonor_after': saml_session_notonor_after,
                } 
    

    def check_saml_security(samlresponse):
        _logger.info("1626897309 INICIO  PENDIENTE SECURITY CON EL CERTIFICADO Y QUITAR TRUE")
        _logger.info("1626897309 FIN PENDIENTE SECURITY CON EL CERTIFICADO Y QUITAR TRUE")
        return True

    def get_authnrequest(self, saml_params):
        _logger.info("1626897310 INICIO AuthnRequest")
        
        _logger.info("1626897310a params: %s", saml_params)

        saml_providers = request.env['auth.saml.provider'].sudo().search_read([
            ('enabled', '=', True),
            ('id','=', saml_params['id']),
            ('name','=', saml_params['name']),
        ], limit=1)

        if len( saml_providers ) == 0:
            return {'error':"Authentication Provider Not Found"}
        
        saml_provider = saml_providers[0]
            
        _logger.info("1626897310b params: %s", saml_provider)
        
        saml = "urn:oasis:names:tc:SAML:2.0:assertion"
        samlp = "urn:oasis:names:tc:SAML:2.0:protocol"

        nss = { 'samlp': samlp,
        'saml': saml,
        }

        dateTimeObj = datetime.utcnow( )
        session_id = http.request.csrf_token()
        
        attribs1 = { 'ID': session_id,
                     'Version': saml_provider['s_version'],
                     'ProviderName': saml_provider['s_provider_name'],
                     'IssueInstant': dateTimeObj.strftime("%Y-%m-%dT%H:%M:%SZ"),
                     'Destination': saml_provider['s_destination_url'],
                     'ProtocolBinding': saml_provider['s_protocol_binding'],
                     'AssertionConsumerServiceURL': saml_provider['s_acs_url'],
                   }
        
        root = etree.Element('{'+ samlp +'}AuthnRequest', nsmap=nss, attrib=attribs1)
        
        #saml_issuer = "http://sp.example.com/demo1/metadata.php"
        saml_issuer = request.httprequest.url_root + "web"
        etree.SubElement(root, "{" + saml + "}Issuer" ).text = saml_issuer

        attribs2 =  { 'Format': saml_provider['s_policy_format'],
                     'AllowCreate': "true",
                    }
        etree.SubElement(root, "{" + samlp + "}NameIDPolicy", attrib=attribs2 )

        attribs3 = { 'Comparison': "exact" }
        RequestedAuthnContext = etree.SubElement(root, "{" + samlp + "}RequestedAuthnContext", attrib=attribs3 )

        etree.SubElement( RequestedAuthnContext, "{" + saml + "}AuthnContextClassRef").text = saml_provider['s_authncontextclassref']

        _logger.info("435 AuthnRequest: %s", etree.tostring( root, pretty_print=True ).decode() )
        
        authnrequest_xml = etree.tostring( root, method="c14n" ).decode()
        
        _logger.info("436 AuthnRequest: %s", authnrequest_xml )
        
        
        #x = requests.post(url, data = myobj)
        headers1 = {'Content-Type': 'application/xml'}
        #url1 = saml_provider['s_destination_url'],
        #url1 = "https://identity.lastpass.com/SAML/SSOService/05fa5c26-9032-48c3-a526-0718b8013e47"
        url1 = "https://identity.lastpass.com/SAML/SSOService"
        r = requests.post(
            url1,
            headers = headers1,
            data = authnrequest_xml,
        )
        
        _logger.info("490==== status_code: %s", r.status_code)
        _logger.info("491==== status_code: %s", r.request)
        _logger.info("492==== status_code: %s", dir(r.request) )
        _logger.info("493==== status_code: %s", r.request)
        _logger.info("494==== status_code: %s", dir(r) )
        _logger.info("495==== status_code: %s", r.request.prepare_url )
        _logger.info("496==== status_code: %s", dir(r.raw) )
        _logger.info("497==== status_code: %s", r.raw.get_redirect_location )
        _logger.info("498==== status_code: %s", r.raw.data )


        _logger.info("493 INICIO get_state")
        redirect = request.params.get('redirect') or 'https://identity.lastpass.com/SAML/SSOService'
        _logger.info("495==== redirect: %s", redirect )
        if not redirect.startswith(('//', 'http://', 'https://')):
            redirect = '%s%s' % (request.httprequest.url_root, redirect[1:] if redirect[0] == '/' else redirect)
        
        #return werkzeug.urls.url_quote_plus(redirect)
        return werkzeug.urls.url_unquote(redirect)
        
        STOP495        
        state = dict(
            d=request.session.db,
            p=provider['id'],
            r=werkzeug.urls.url_quote_plus(redirect),
        )
        token = request.params.get('token')
        if token:
            state['t'] = token
        
        

        if r.status_code != 200:
            _logger.info("CODE: %s TEXT: %s", r.status_code,r.text)
            return "Destination URL Error: " + r.status_code

        
        STOP492
        
        return {'saml_form': r.text}
        
        
        _logger.info("451 SAMLResponse: %s", r )
        _logger.info("452 SAMLResponse: %s", r.status_code )
        _logger.info("453 SAMLResponse: %s", r.headers['content-type'] )
        _logger.info("454 SAMLResponse: %s", r.text )
        _logger.info("455 SAMLResponse: %s", dir(r) )
        STOP380
        return "WIP"