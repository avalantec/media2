# -*- coding: utf-8 -*-
import odoo
from odoo import http
from odoo import api, SUPERUSER_ID
from odoo import registry as registry_get
from lxml import etree


from datetime import datetime

import requests
import werkzeug
import base64
#from werkzeug.urls import url_encode
#from werkzeug.urls import url_join

import logging
_logger = logging.getLogger(__name__)
asdfasdfestoqhaceunerror

class AuthSaml(http.Controller):

    @http.route('/web/auth_saml/acs/', auth='public', methods=['GET', 'POST'],csrf=False )
    def index(self, redirect=None, **kw):
        _logger.info("1626897201 route web/auth_saml/acs def index")

        saml_endpoint = "https://avalantec-dev.onelogin.com/trust/saml2/http-post/sso/6d8b170b-b1e9-494f-8caf-92f878ec79d3"
        
        if http.request.httprequest.method == 'POST':
            _logger.info("1626897201a method POST %s", kw)
            
            saml_response = kw.get('SAMLResponse')
            
            response1 = base64.b64decode( saml_response ).decode('utf-8')
            _logger.info("1626897201b RESPONSE\n%s\n", response1 )
            
            
            _logger.info("1626897201c PENDINENTER VALIDAR EL SIGNATURE Y CERTIFICADO" )
            #InProgress==================
            headers = {
                'Content-Type': 'text/html',
            }
            url = "https://stefanjaw-demo-media3-saml-2899727.dev.odoo.com/web/login"
            data1 = "csrf_token=d2ef43511a9bf6c1680f355e0ab2a532a34251e6o1658501833&login=dfgbdfgb&password=azfgdsfg&redirect="

            '''data1 = {
                'session_id': 999999,
            }
            '''
            
            r = requests.post(url, data=data1, headers=headers, timeout=65)
            
            #InProgress==================
            _logger.info("1626897201d r %s", r)
            
            return response1

        if http.request.httprequest.method == 'GET':
            _logger.info("37====DEB http request method GET")
            
            # ensure_db() para definir 
            result = http.request.params.get('db')# and request.params.get('db').strip()
            _logger.info("77777===DEB result %s", result) # Devuelve NONE estando con o sin login
            
            http.request.params['login_success'] = False #Garantiza que no envíen un request con true

            if not http.request.uid:
                http.request.uid = SUPERUSER_ID
            
            _logger.info("77777b===DEB request params %s", http.request.params)
            _logger.info("77777c===DEB request uid %s", http.request.uid)
            
            values = http.request.params.copy()
            try:
                values['databases'] = http.db_list()
            except odoo.exceptions.AccessDenied:
                values['databases'] = None
            
            _logger.info("77777d web_login values: %s", values)
            
            #Buscar el usuario
            
            #TEMPORAL PARA LAS PRUEBAS
            #http.request.params['login'] = "test1@l.localhost"
            #http.request.params['password'] = "0987654321"
            
            # Metodo http.request.session.authenticate es para usuario y password únicamente
            # si no se coloca password da un error
            '''
            uid = http.request.session.authenticate(
                        http.request.session.db,
                        http.request.params['login'],
                        #http.request.params['password']
                    )
            '''
            uid = 3
            #http.request.session.uid = uid
            
            #http.request.uid = uid
            #_logger.info("77777ee http.request.uid %s", http.request.uid)
            
            http.request.params['login_success'] = True
            _logger.info("77777e request_uid UID: %s", uid)
            _logger.info("77777f===DEB request params %s", http.request.params)
            redirect = "/web"
            output = http.redirect_with_hash(self._login_redirect(uid, redirect=redirect))
            return output
            #redirect = "/blablabla"
            #return http.redirect_with_hash(redirect)
            return "88888"
            STOP60
            
            
            _logger.info("40===DEB Define ID and name from http request")
            data_id = kw.get('id')
            data_name = kw.get('name')
            
            
            if data_id == None:
                _logger.info("46=== NO CONTIENE EL ID")
                return "DATA INCOMPLETE"
            
            filter = [('id','=', data_id),('name','=', data_name)]
            auth_saml_provider = http.request.env['auth.saml.provider'].sudo().search_read(filter,limit=1)
            
            if len(auth_saml_provider) < 1:
                return "UNKNOWN DATA"
            
            _logger.info("55=== DEB Data validation OK")
            
            _logger.info("57=== DEB CONSTRUYENDO EL XML")

            session_id = "909099809707f0030a5d00620c9d9df97f627afe9dcc24"
            
            data = {
                'session_id': session_id,
                'provider_name': auth_saml_provider[0]['provider_name'],
                'version': auth_saml_provider[0]['version'],
                'destination_url': auth_saml_provider[0]['destination_url'],
                'protocol_binding': auth_saml_provider[0]['protocol_binding'],
                'acs_url': auth_saml_provider[0]['acs_url'],
                'issuer_url': auth_saml_provider[0]['issuer_url'],
                'policy_format': auth_saml_provider[0]['policy_format'],
                'authncontextclassref': auth_saml_provider[0]['authncontextclassref'],
            }
            xml_transaction = self.xml_request_build(data)
            _logger.info("65==CONTROLLER= DEB CONSTRUYENDO EL XML FIIIIIN \n%s\n", xml_transaction)
            
            _logger.info( "76=CONTROLLER== DEB REQUEST SESSION UID: %s", http.request.session.uid )
            
            _logger.info( "78==CONTROLLER== DEB REQUEST PARAMS TOKEN: %s", http.request.params.get('token') )
            
            headers = {
                'Content-Type': 'text/xml',
            }
            
            url = auth_saml_provider[0]['saml_endpoint_url']
            _logger.info("85=====DEB URL %s", url)
            
            r = requests.post(url, data=xml_transaction, headers=headers, timeout=65)
            r.raise_for_status()
            
            _logger.info("90== R %s", r)
            
            response = werkzeug.utils.unescape(r.content.decode())
            _logger.info("93== RESPONSE %s", response)
            
            return response
            

        return "ERROR: NO POST OR GET"

    def xml_request_build(self,data):
        _logger.info("1626897202")
        
        samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        saml="urn:oasis:names:tc:SAML:2.0:assertion"
        NS={"samlp": samlp, "saml": saml}
        
        

        
        _logger.info("119====XXXXXXPENDIENTE VALIDACIONES IF EXISTE PARA CADA CAMPO\n\n\n")
        
        attributes={
            'ID': data['session_id'],
            'Version': data['version'],
            'ProviderName': data['provider_name'],
            'IssueInstant': datetime.utcnow().isoformat()[:-7]+'Z',
            'Destination': data['destination_url'],
            'ProtocolBinding': data['protocol_binding'],
            'AssertionConsumerServiceURL': data['acs_url'],
        }
        _logger.info("128====DEB ATTRIBS: \n%s\n", attributes)
        authnrequest = etree.Element( "{"+ samlp + "}AuthnRequest", nsmap=NS,attrib=attributes )
        
        etree.SubElement(authnrequest, "{" + saml + "}Issuer").text = data['issuer_url']
        attributes={
             'Format': data['policy_format'],
             'AllowCreate': "true",
        }
        etree.SubElement(authnrequest, "{" + samlp + "}NameIDPolicy", attrib=attributes)
        
        attributes={
             'Comparison': 'exact',
        }
        RequestedAuthnContext= etree.SubElement(authnrequest, "{" + samlp + "}RequestedAuthnContext", attrib=attributes)
        
        etree.SubElement(RequestedAuthnContext, "{" + saml + "}AuthnContextClassRef").text = data['authncontextclassref']
        
        xml_saml_request = etree.tostring(authnrequest, xml_declaration=True, pretty_print=True, encoding='utf-8').decode()
        
        _logger.info("131====DEB xml_saml_request \n%s\n", xml_saml_request)

        return xml_saml_request
    
    def _login_redirect(self, uid, redirect=None):
        _logger.info("162689758 INICIO _login_redirect")
        output = _get_login_redirect_url(uid, redirect)
        _logger.info("162689758 FIN _login_redirect output %s", output)
        return output
    
    
def _get_login_redirect_url(uid, redirect=None):
    """ Decide if user requires a specific post-login redirect, e.g. for 2FA, or if they are
    fully logged and can proceed to the requested URL
    """
    if http.request.session.uid: # fully logged
        return redirect or '/web'

    # partial session (MFA)
    url = http.request.env(user=uid)['res.users'].browse(uid)._mfa_url()
    if not redirect:
        return url

    #XXX TEMPORAL DA ERROR AL BUSCAR EL URL
    _logger.info("77777x URL %s", url )
    if not url: #prueba
        url = "/" #prueba


    parsed = werkzeug.urls.url_parse(url)
    qs = parsed.decode_query()
    qs['redirect'] = redirect

    
    output = parsed.replace(query=werkzeug.urls.url_encode(qs)).to_url()
    _logger.info("77777z output %s", output )
    return output
    
    
    
    
