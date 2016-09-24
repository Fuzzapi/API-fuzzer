class PingController < ActionController::Base
  def index
    sha = params[:id]
    scan = Scan.find_by_sid(sha)
    scan.vulnerabilities.create!(
      status: 'HIGH',
      class_type: 'Vulnerability',
      description: 'Possible XXE vulnerability in #{scan.url}',
      value: params[:body]
    ) if scan
    render :ok
  end
end
