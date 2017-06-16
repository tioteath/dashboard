require 'time'
require 'sinatra'
require 'warden/github'
require 'pg'
require 'socket'
require 'yaml'

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

    set :postgresql_connection do
      PG.connect dbname: ENV['POSTGRESQL_DATABASE'] || 'postgres'
    end

    set :hostname do
      Socket.gethostname
    end

    set :organization_authorized do
      v = ENV['GITHUB_ORGANIZATION_AUTHORIZED'] || []
      if v.is_a? String
        v.split ' '
      else
        v
      end
    end

    set :team_authorized do
      v = ENV['GITHUB_TEAM_AUTHORIZED'] || []
      if v.is_a? String
        v.split ' '
      else
        v
      end
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
        @slow_queries = settings.postgresql_connection.exec "SELECT query,
            calls, total_time, rows, 100.0 * shared_blks_hit / 
            nullif(shared_blks_hit + shared_blks_read, 0) AS hit_percent
            FROM pg_stat_statements ORDER BY total_time DESC LIMIT 50;"

        erb :index
      else
        redirect '/login'
      end
    end

    get '/access_denied' do
      env['warden'].logout
      status 403
      erb :access_denied
    end

    get '/login' do
      verify_browser_session
      env['warden'].authenticate!
      redirect '/'
    end

    get '/logout' do
      env['warden'].logout
      erb :log_out
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
<div class="alert alert-warning"><strong>Access denied</strong><p><%= env['warden'].message %></p></div>

@@log_out
<div class="alert alert-info"><strong>Logged out</strong></div>

@@ layout
<!DOCTYPE html>
<html lang="en">
<head>
<% if authenticated? %>
  <title>Slow queries at <%= settings.hostname %></title>
<% end %>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
  <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>
<style>
.glyphicon { margin-right: 4px; } <!-- dirty fix for one's stupidity https://github.com/twbs/bootstrap/issues/2263#issuecomment-4189145 -->
.navbar-nav > li > a, .navbar-brand {
padding-top:1px !important; padding-bottom:0 !important;
height: 15px;
}
.navbar {min-height:30px !important;}
</style>
</head>
<body>
<%= yield %>
<div class="navbar navbar-inverse navbar-fixed-bottom"><div class="navbar-inner"><div class="container text-center">
<ul class="nav navbar-nav">
<% if authenticated? %>
<li><p class="navbar-text"><%= env['warden'].user.login %>@<%= settings.hostname %></p></li>
<% end %>
<li><p class="navbar-text"><%= Time.now.utc.iso8601 %></p></li>
</ul>
<ul class="nav navbar-nav navbar-right">
<% if authenticated? %>
<li><a href="/logout"><span class="glyphicon glyphicon-log-out"></span>Logout</a></li>
<% else %>
<li><a href="/login"><span class="glyphicon glyphicon-log-in"></span>Login</a></li>
<% end %>
</ul>
</div></div></div>
</body>
</html>

@@ index
<div class="jumbotron"><div class="container"><div class="table-responsive"><table class="table">
<h2>Slow queries at <%= settings.hostname %></h2>
<tr>
<th>total_time</th>
<th>query</th>
<th>calls</th>
<th>rows</th>
<th>hit_percent</th>
</tr>
<% @slow_queries.each do |item| %>
<tr>
<td><%= item['total_time'] %></td>
<td><%= item['query'] %></td>
<td><%= item['calls'] %></td>
<td><%= item['rows'] %></td>
<td><%= item['hit_percent'] %></td>
</tr>
<% end %>
</table></div></div></div>
