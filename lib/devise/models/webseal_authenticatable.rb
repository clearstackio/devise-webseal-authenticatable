require 'websealtar'
require 'devise/strategies/webseal_authenticatable'

module Devise
  module Models
    # The WebsealAuthenticatable module is responsible for validating a user's credentials
    # behind a webseal proxy server.  When authentication is successful, the
    # attributes set by the webseal server are made available via the
    # +webseal_attributes+ accessor in the user model.
    #
    # The WebsealAuthenticatable module works by using the configured
    # +webseal_uid_generator+ to generate a UID based on the username and the webseal server
    # hostname or IP address.  This UID is used to see if an existing record representing
    # the user already exists.  If it does, webseal authentication proceeds through that
    # user record.  Otherwise, a new user record is built and authentication proceeds.
    # If authentication is successful, the +after_webseal_authentication+ callback is
    # invoked, the default implementation of which simply saves the user record with
    # validations disabled.
    #
    # The webseal username is extracted from the parameters hash by using the first
    # configured value in the +Devise.authentication_keys+ array.  If the authentication
    # key is in the list of case insensitive keys, the username will be converted to
    # lowercase prior to authentication.
    #
    # == Options
    #
    # WebsealAuthenticable adds the following options to devise_for:
    # * +webseal_server+: The hostname or IP address of the webseal server.
    # * +webseal_server_port+: The port the webseal server is listening on.
    # * +webseal_server_secret+: The shared secret configured on the webseal server.
    # * +webseal_server_timeout+: The number of seconds to wait for a response from the
    #   webseal server.
    # * +webseal_server_retries+: The number of times to retry a request to the webseal
    #   server.
    # * +webseal_uid_field+: The database column to store the UID in
    # * +webseal_uid_generator+: A proc that takes the username and server as parameters
    #   and returns a string representing the UID
    # * +webseal_dictionary_path+: The path containing the webseal dictionary files to load
    # * +handle_webseal_timeout_as_failure+: Option to handle webseal timeout as authentication failure
    #
    # == Callbacks
    #
    # The +after_webseal_authentication+ callback is invoked on the user record when
    # webseal authentication succeeds for that user but prior to Devise checking if the
    # user is active for authentication.  Its default implementation simply saves the
    # user record with validations disabled.  This method should be overriden if further
    # actions should be taken to make the user valid or active for authentication.  If
    # you override it, be sure to either call super to save the record or to save the
    # record yourself.
    module WebsealAuthenticatable
      extend ActiveSupport::Concern

      included do
        attr_accessor :webseal_attributes
      end

      # Use the currently configured webseal server to attempt to authenticate the
      # supplied username and password.  If authentication succeeds, make the webseal
      # attributes returned by the server available via the webseal_attributes accessor.
      # Returns true if authentication was successful and false otherwise.
      #
      # Parameters::
      # * +username+: The username to send to the webseal server
      # * +password+: The password to send to the webseal server
      def valid_webseal_password?(username, password)
        server = self.class.webseal_server
        port = self.class.webseal_server_port
        secret = self.class.webseal_server_secret
        options = {
          :reply_timeout => self.class.webseal_server_timeout,
          :retries_number => self.class.webseal_server_retries
        }
        if self.class.webseal_dictionary_path
          options[:dict] = Websealtar::Dictionary.new(self.class.webseal_dictionary_path)
        end

        req = Websealtar::Request.new("#{server}:#{port}", options)

        # The authenticate method will raise a RuntimeError if we time
        # out waiting for a response from the server.
        begin
          reply = req.authenticate(username, password, secret)
        rescue
          return false if self.class.handle_webseal_timeout_as_failure
          raise
        end

        if reply[:code] == 'Access-Accept'
          reply.extract!(:code)
          self.webseal_attributes = reply
          true
        else
          false
        end
      end

      # Callback invoked by the WebsealAuthenticatable strategy after authentication
      # with the webseal server has succeeded and devise has indicated the model is valid.
      # This callback is invoked prior to devise checking if the model is active for
      # authentication.
      def after_webseal_authentication
        self.save(:validate => false)
      end

      module ClassMethods

        Devise::Models.config(self, :webseal_server, :webseal_server_port,
                              :webseal_server_secret, :webseal_server_timeout,
                              :webseal_server_retries, :webseal_uid_field,
                              :webseal_uid_generator, :webseal_dictionary_path,
                              :handle_webseal_timeout_as_failure)

        # Invoked by the WebsealAuthenticatable stratgey to perform the authentication
        # against the webseal server.  The username is extracted from the authentication
        # hash and a UID is generated from the username and server IP.  We then search
        # for an existing resource using the UID and configured UID field.  If no resource
        # is found, a new resource is built (not created).  If authentication is
        # successful the callback is responsible for saving the resource.  Returns the
        # resource if authentication succeeds and nil if it does not.
        def find_for_webseal_authentication(authentication_hash)
          uid_field = self.webseal_uid_field.to_sym
          username, password = webseal_credentials(authentication_hash)
          uid = self.webseal_uid_generator.call(username, self.webseal_server)

          resource = find_for_authentication({ uid_field => uid }) ||
            new(uid_field => uid)

          resource.valid_webseal_password?(username, password) ? resource : nil
        end

        # Extract the username and password from the supplied authentication hash.  The
        # username is extracted using the first value from +Devise.authentication_keys+.
        # The username is converted to lowercase if the authentication key is in the list
        # of case insensitive keys configured for Devise.
        def webseal_credentials(authentication_hash)
          key = self.authentication_keys.first
          value = authentication_hash[key]
          value.downcase! if (self.case_insensitive_keys || []).include?(key)

          [value, authentication_hash[:password]]
        end
      end
    end
  end
end
