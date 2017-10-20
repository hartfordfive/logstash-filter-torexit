# encoding: utf-8
require_relative '../spec_helper'
require "logstash/filters/torexit"

describe LogStash::Filters::Torexit do

  describe "Validate address IS tor exit node" do
    let(:config) do <<-CONFIG
      filter {
        torexit {
          source => "clientip"
          exit_node_list_file => "./exit-addresses.sample"
        }
      }
    CONFIG
    end

    sample("user_agent" => "Firefox", "clientip" => "199.249.223.62") do
      insist { subject.get("tags") } == ["_tor_exit_node"]
    end
  end


  describe "Validate address IS NOT tor exit node" do
    let(:config) do <<-CONFIG
      filter {
        torexit {
          source => "clientip"
          update_period => 10
          exit_node_list_file => "./exit-addresses.sample"
        }
      }
    CONFIG
    end

    sample("user_agent" => "Internet Explorer", "clientip" => "216.104.96.10") do
      insist { subject.get("tags") } != ["_tor_exit_node"]
    end
  end

  describe "Wait for IP list to update and then validate address IS NOT tor exit node" do
    let(:config) do <<-CONFIG
      filter {
        torexit {
          source => "clientip"
          update_period => 10
          exit_node_list_file => "./exit-addresses.sample"
        }
      }
    CONFIG
    end
    #puts "Sleeping 10 seconds..."
    #sleep 10
    sample("user_agent" => "Chrome", "clientip" => "216.104.96.10") do
      insist { subject.get("tags") } != ["_tor_exit_node"]
    end
  end

end
