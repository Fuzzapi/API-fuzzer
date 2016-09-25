class PingController < ActionController::Base
  def index
    @scan = Scan.find(params[:id])
    @scan.vulnerabilities.create!(
      status: 'HIGH',
      class_type: 'Vulnerability',
      description: "Possible XXE vulnerability in #{@scan.url}",
      value: body
    ) if @scan
    render json: { status: :ok }
  end

  def pong
    render json: { status: :ok }
  end

  private

  def body
    @scan.parameters.gsub(/\>\s*[a-zA-Z0-9]*\s*\<\//, '>&xxe;<')
  end
end
