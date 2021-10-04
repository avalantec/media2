# -*- coding: utf-8 -*-

from odoo import models, fields, api

import logging
_logger = logging.getLogger(__name__)

from odoo.exceptions import ValidationError

from odoo import _
import requests
import json


class auth_saml(models.Model):
    _inherit = "res.partner"
    
    x_response = fields.Text()
    
    @api.model
    def saml_request(self, values):
        _logger.info("1626897401")
        _logger.info("1626897401a self %s  values %s", self, values)
        
        ONELOGIN_ENDPOINT = "https://www.onelogin.com/"
                
        headers = {} #{"content-type": "application/x-www-form-urlencoded"}
        data = {
            'code': "authorize_code",
        }
        
        TIMEOUT = 60
        method = "POST"
        
        #base_url = "https://maps.googleapis.com/maps/api/geocode/json?"
        #base_url = "https://www.onelogin.com"
        base_url = "https://httpbin.org/anything"
        
        params = {
            'address': "43230, OH, USA",
            'key': "AIzaSyAU………..1ycBkPVM6Y-c"
        }
        params = {}
        
        r= requests.post(base_url, params)
        #r= requests.post(base_url, params)
        if r.status_code == 200:
            _logger.info("45=====R.TEXT \n%s",r.text )   # Obtiene la respuesta en formato TEXTO
            #_logger.info("R.TEXT-JSON \n%s",r.json() )   # Obtiene la respuesta en formato JSON
        _logger.info("47==== R %s", r.status_code)
        
        client_action = {
            'type': 'ir.actions.act_url',
            'name': "Shipment Tracking Page",
            'target': 'new',
            #'url': self.carrier_tracking_url,
            'url': base_url,
        }
        return client_action