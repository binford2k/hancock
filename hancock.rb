#! /usr/bin/env ruby

require 'rubygems'
require 'sinatra/base'
require 'webrick'
require 'webrick/https'
require 'openssl'
require 'resolv'

PUPPET    = '/opt/puppet/bin/puppet'
CERT_PATH = 'certs'
USER      = 'admin'
PASSWORD  = 'admin'


opts = {
        :Port               => 8080,
        :Logger             => WEBrick::Log::new($stderr, WEBrick::Log::DEBUG),
        :SSLEnable          => true,
        :SSLVerifyClient    => OpenSSL::SSL::VERIFY_NONE,
        :SSLCertificate     => OpenSSL::X509::Certificate.new(  File.open(File.join(CERT_PATH, 'server.crt')).read),
        :SSLPrivateKey      => OpenSSL::PKey::RSA.new(          File.open(File.join(CERT_PATH, 'server.key')).read),
        :SSLCertName        => [ [ "CN",WEBrick::Utils::getservername ] ]
}

class Server  < Sinatra::Base

    set :public, 'public'
    
    get '/' do
      protected!
      @certs = load_certs()
      erb :certs
    end
       
    get '/list' do
      protected!
      @certs = load_certs(:all)
      erb :certs
    end

    get '/sign/:certname' do |certname|
      protected!
      @certs = load_certs(:all)
      action(:sign, certname)
    end

    get '/revoke/:certname' do |certname|
      protected!
      @certs = load_certs(:all)
      action(:revoke, certname)
    end

    get '/clean/:certname' do |certname|
      protected!
      @certs = load_certs(:all)
      action(:clean, certname)
    end
    
    get '/autosign/:fingerprint' do |fingerprint|
      @certs = load_certs()
      begin
        host = Resolv.new.getname(request.ip)
        if(@certs[host][:fingerprint] == fingerprint)
          action(:sign, host) 
        end
      rescue
        json(:status => :fail, :message => "Cannot sign certificate.")
      end
    end
    
    not_found do
      halt 404, 'page not found'
    end
    
    helpers do

      def action(action, certname)
        if @certs.has_key?(certname)
          begin
            case action
            when :sign
              %x[#{PUPPET} cert sign #{certname}]
              json(:status => :success, :message => "Signed certificate for #{certname}.")
            when :revoke
              %x[#{PUPPET} cert revoke #{certname}]
              json(:status => :success, :message => "Revoked certificate for #{certname}.")
            when :clean
              %x[#{PUPPET} cert clean #{certname}]
              json(:status => :success, :message => "Cleaned certificate for #{certname}.")
            else
              raise
            end
          rescue
            json(:status => :fail, :message => "Action failed.")
          end
        else
          json(:status => :fail, :message => "No certificate for #{certname}.")
        end
      end
      
      # returns a hash of certificates, keyed on certname
      #
      # cert[name] => {
      #                        :status => status,
      #                   :fingerprint => fingerprint,
      #                 :dns_alt_names => [dns_alt_names, ],
      #               }
      #
      def load_certs(format=:outstanding)
        certs = {}
        all = (format == :all ? ' --all':'')
        %x[#{PUPPET} cert list #{all}].each_line do |l|
          line = l.split
          # normalize for cases with no status
          line.unshift(nil) if line.length < 3
          # ignore all internal certs
          next if line[1] =~ /^pe-internal-/
          certs[line[1]] = {
                             :status        => line[0],
                             :fingerprint   => line[2].gsub(/[()]/, ''),
                             :dns_alt_names => line[5, line.length],
                           }
        end

        certs
      end
      
      # define my own dinky jsonifier so I don't have to depend on JSON
      def json(args)
        str = '{'
        args.each { |arg, val| str << "\"#{arg.to_s}\":\"#{val.to_s}\", " }
        str.chomp!(', ') << '}'
      end

      # Basic auth boilerplate
      def protected!
        unless authorized?
          response['WWW-Authenticate'] = %(Basic realm="Restricted Area")
          throw(:halt, [401, "Not authorized\n"])
        end
      end
      
      def authorized?
        @auth ||=  Rack::Auth::Basic::Request.new(request.env)
        @auth.provided? && @auth.basic? && @auth.credentials && @auth.credentials == [USER, PASSWORD]
      end

    end    
end

Rack::Handler::WEBrick.run(Server, opts) do |server|
        [:INT, :TERM].each { |sig| trap(sig) { server.stop } }
end
