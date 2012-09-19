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
      @certs = load_certs()
      sign(certname)
    end
    
    get '/autosign/:fingerprint' do |fingerprint|
      @certs = load_certs()
      begin
        host = Resolv.new.getname(request.ip)
        puts "trying #{host}"
        p @certs
        p fingerprint
        if(@certs[host][:fingerprint] == fingerprint)
          sign(host) 
        else
          "{\"status\":\"fail\", \"message\":\"Fingerprint doesn't match #{fingerprint}.\"}"
        end
      rescue
        "{\"status\":\"fail\", \"message\":\"No DNS entry for #{request.ip}.\"}"
      end
    end
    
    not_found do
      halt 404, 'page not found'
    end
    
    helpers do

      def sign(certname)
        puts "signing #{certname}"
        if @certs.has_key?(certname)
          begin
            %x[#{PUPPET} cert sign #{certname}]
            "{\"status\":\"success\", \"message\":\"Signed certificate for #{certname}.\"}"
          rescue
            "{\"status\":\"fail\", \"message\":\"Signing request failed.\"}"
          end
        else
          "{\"status\":\"fail\", \"message\":\"No CSR for #{certname}.\"}"
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
