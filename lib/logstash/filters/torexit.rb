# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "ipaddress"

# This  filter will replace the contents of the default 
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an .
class LogStash::Filters::Torexit < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  config_name "torexit"

  # Replace the message with this value.
  config :exit_node_list_file, :validate => :string, :required => false
  config :source, :validate => :string, :required => true
  config :tag_on_success, :validate => :array, :default => ["_tor_exit_node"]
  config :update_period, :validate => :number, :default => 86400

  public
  def register

    @exit_node_list = {}
    @logger.debug("First run to build list of tor exit nodes...")
    populate_exit_node_list()

  end # def register

  public
  def filter(event)

    ip = event.get(@source)
    if !ip
      @logger.error("Required IP source field '#{@source}' field is missing.")
      return
    elsif !IPAddress.valid?(ip)
      @logger.error("IP #{ip} is invalid!")
      return
    end

    @tag_on_success.each{|tag| event.tag(tag)} if @exit_node_list[ip]

    filter_matched(event)
  end # def filter

  def populate_exit_node_list()

    contents = File.read(@exit_node_list_file)

    exit_nodes = contents.scan /^ExitNode(?:(?!ExitNode).)*/m
    exit_nodes.each do |node|

      exit_node_id = nil
      published_date = nil
      last_status_date = nil
      exit_node_address = nil
      last_addr_confirmation = nil

      node.split("\n").each do |line|
        parts = line.strip.split(' ')
        if parts[0].strip == "ExitNode"
        exit_node_id = parts[1]
        elsif parts[0].strip == "Published"
          published_date = "#{parts[1]} #{parts[2]}"
        elsif parts[0].strip == "LastStatus"
          last_status_date = "#{parts[1]} #{parts[2]}"
        elsif parts[0].strip == "ExitAddress"
          exit_node_address = parts[1]
          last_addr_confirmation = "#{parts[2]} #{parts[3]}"
        end
      end

      @exit_node_list[exit_node_address] = {
        "exit_node" => exit_node_id,
        "published_date" => published_date,
        "last_status_date" => last_status_date,
        "last_address_confirmation" => last_addr_confirmation
      }

    end

    @logger.debug("Node list: ", :exit_nodes => @exit_node_list_url)

  end # def update_exit_node_list

end # class LogStash::Filters::Torexit


