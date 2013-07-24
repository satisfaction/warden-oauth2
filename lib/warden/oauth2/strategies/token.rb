require 'warden-oauth2'

module Warden
  module OAuth2
    module Strategies
      class Token < Client
        def valid?
          !!token_string
        end

        def authenticate!
          client = client_from_http_basic || client_from_request_params

          if client && token
            fail! "invalid_token" and return if token.respond_to?(:expired?) && token.expired?
            fail! "insufficient_scope" and return if scope && token.respond_to?(:scope?) && !token.scope?(scope, env)
            success! token, client
          else
            fail! "invalid_request" and return unless token
          end
        end

        def token
          @token ||= Warden::OAuth2.config.token_model.locate(token_string)
        end

        def token_string
          raise NotImplementedError
        end

        def error_status
          case message
            when "invalid_token" then 401
            when "insufficient_scope" then 403
            when "invalid_request" then 400
            else 400
          end
        end
      end
    end
  end
end
