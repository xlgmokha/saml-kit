require 'rails_helper'

describe ComputersController do
  describe "#index" do
    let(:access_token) { SecureRandom.uuid }
    let(:computer) do
      {
        "connector_guid": "ad29d359-dac9-4940-9c7e-c50e6d32ee6f",
        "hostname": "Demo_CozyDuke",
        "active": true,
        "links": {
          "computer": "https://portal.dev/v1/computers/ad29d359-dac9-4940-9c7e-c50e6d32ee6f",
          "trajectory": "https://portal.dev/v1/computers/ad29d359-dac9-4940-9c7e-c50e6d32ee6f/trajectory",
          "group": "https://portal.dev/v1/groups/b077d6bc-bbdf-42f7-8838-a06053fbd98a"
        },
        "connector_version": "4.1.7.10201",
        "operating_system": "Windows 7, SP 1.0",
        "internal_ips": [ "87.27.44.37" ],
        "external_ip": "93.111.140.204",
        "group_guid": "b077d6bc-bbdf-42f7-8838-a06053fbd98a",
        "install_date": "2016-05-20T19:20:00Z",
        "network_addresses": [ { "mac": "09:de:6b:a8:74:10", "ip": "87.27.44.37" } ],
        "policy": { "guid": "89912c9e-8dbd-4c2b-a1d8-dee8a0c2bb29", "name": "Audit Policy" }
      }
    end

    it 'fetches all the computers' do
      response_body = {
        "version": "v1.2.0",
        "metadata": {
          "links": { "self": "https://portal.dev/v1/computers" },
          "results": { "total": 1, "current_item_count": 1, "index": 0, "items_per_page": 500 }
        },
        "data": [ computer ]
      }

      stub_request(:get, "https://portal.dev/v1/computers/").
        with(headers: { 'Authorization' => "Bearer #{access_token}", 'Accept'=>'application/json', 'Content-Type'=>'application/json'}).
        to_return(status: 201, body: response_body.to_json)

      session[:access_token] = access_token

      get :index

      expect(response).to have_http_status(:ok)
      expect(assigns(:computers)).to match_array([computer])
    end
  end
end
