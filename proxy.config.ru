require 'time'
require 'sinatra'
require 'warden/github'
require 'socket'
require 'yaml'
require 'haml'

module Sinatra

  class SinatraApp < Sinatra::Base
    include Warden::GitHub::SSO

    GITHUB_CONFIG = {
      client_id:     ENV['GITHUB_CLIENT_ID']     || 'test_client_id',
      client_secret: ENV['GITHUB_CLIENT_SECRET'] || 'test_client_secret',
      scope:         'user'
    }

    enable  :sessions
    enable  :raise_errors
    disable :show_exceptions
    enable :inline_templates

    use Warden::Manager do |config|
      config.default_strategies :github
      config.scope_defaults :default, config: GITHUB_CONFIG
      config.serialize_from_session { |key| Warden::GitHub::Verifier.load(key) }
      config.serialize_into_session { |user| Warden::GitHub::Verifier.dump(user) }
    end

    set :bind, '0.0.0.0'
    set :port, 9292

    set :hostname do
      Socket.gethostname
    end

    set :organization_authorized do
      v = ENV['GITHUB_ORGANIZATION_AUTHORIZED'] || []
      if v.is_a? String then v.split ' ' else v end
    end

    set :team_authorized do
      v = ENV['GITHUB_TEAM_AUTHORIZED'] || []
      if v.is_a? String then v.split ' ' else v end
    end

    def verify_browser_session
      if env['warden'].user && !warden_github_sso_session_valid?(env['warden'].user, 10)
        env['warden'].logout
        redirect '/logout'
      end
    end

    def authorized?
      settings.organization_authorized.each do |organization|
        return true if env['warden'].user.organization_member? organization or
            env['warden'].user.organization_public_member? organization
      end
      settings.team_authorized.each do |team|
        return true if env['warden'].user.team_member? team
      end
      false
    end

    def authenticated?
      env['warden'].authenticated?
    end

    get '/debug' do
      verify_browser_session
      env['warden'].authenticate!
      content_type :text
      env['rack.session'].to_yaml
    end

    get '/' do
      if authenticated?
        verify_browser_session
        redirect '/access_denied' unless authorized?

        haml :index
      else
        redirect '/login'
      end
    end

    get '/access_denied' do
      env['warden'].logout
      status 403
      haml :access_denied
    end

    get '/login' do
      verify_browser_session
      env['warden'].authenticate!
      redirect '/'
    end

    get '/logout' do
      env['warden'].logout
      haml :log_out
    end
  end

  def self.app
    @app ||= Rack::Builder.new do
      run SinatraApp
    end
  end
end

# start the server if ruby file executed directly
# run! if app_file == $0
run Sinatra.app

__END__

@@ access_denied
.alert.alert-warning
  %strong Access denied
  %p= env['warden'].message

@@ log_out
.alert.alert-info
  %strong Logged out

@@ layout
!!!
%html{:lang => "en"}
  %head
    %meta{:content => "text/html; charset=UTF-8", "http-equiv" => "Content-Type"}/
    - if authenticated?
      %title
        Slow queries at #{settings.hostname}
    %meta{:charset => "utf-8"}/
    %meta{:content => "width=device-width, initial-scale=1", :name => "viewport"}/
    %link{:href => "https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css", :rel => "stylesheet"}/
    %script{:src => "https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"}
  :css
    .glyphicon { margin-right: 4px; }
  %body
    = yield
    .navbar.navbar-inverse.navbar-fixed-bottom
      .navbar-inner
        .container.text-center
          %ul.nav.navbar-nav
            - if authenticated?
              %li
                %p.navbar-text
                  = env['warden'].user.login
                  @#{settings.hostname}
            %li
              %p.navbar-text= Time.now.utc.iso8601
          %ul.nav.navbar-nav.navbar-right
            - if authenticated?
              %li
                %a{:href => "/logout"}
                  %span.glyphicon.glyphicon-log-out>
                  Logout
            - else
              %li
                %a{:href => "/login"}
                  %span.glyphicon.glyphicon-log-in>
                  Login

@@index
.alert.alert-info
  %strong Access granted

