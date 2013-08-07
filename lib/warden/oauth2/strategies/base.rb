require 'warden-oauth2'

module Warden
  module OAuth2
    module Strategies
      class Base < Warden::Strategies::Base
        def store?
          false
        end

        def error_status
          400
        end
        
        def parameters
          @env["action_dispatch.request.parameters"] ||= begin
            params = request_parameters.merge(query_parameters)
            params.merge!(path_parameters)
            encode_params(params).with_indifferent_access
          end
        end
      end
    end
  end
end
