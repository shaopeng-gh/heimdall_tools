require 'json'
require 'csv'
require 'heimdall_tools/hdf'

RESOURCE_DIR = Pathname.new(__FILE__).join('../../data')

CWE_NIST_MAPPING_FILE = File.join(RESOURCE_DIR, 'cwe-nist-mapping.csv')

IMPACT_MAPPING = {
  error: 0.7,
  warning: 0.5,
  note: 0.3,
  none: 0.0
}.freeze

DEFAULT_NIST_TAG = %w{SA-11 RA-5}.freeze

# Loading spinner sign
$spinner = Enumerator.new do |e|
  loop do
    e.yield '|'
    e.yield '/'
    e.yield '-'
    e.yield '\\'
  end
end

module HeimdallTools
  class SarifMapper
    def initialize(sarif_json, _name = nil, verbose = false)
      @sarif_json = sarif_json
      @verbose = verbose
      begin
        @cwe_nist_mapping = parse_mapper
        @sarif_log = JSON.parse(@sarif_json)
      rescue StandardError => e
        raise "Invalid SARIF JSON file provided\n\nException: #{e}"
      end
    end

    def extract_scaninfo(sarif_log)
      info = {}
      begin
        info['policy'] = 'SARIF'
        info['version'] = sarif_log['version']
        info['projectName'] = 'Static Analysis Results Interchange Format'
        info['summary'] = NA_STRING
        info
      rescue StandardError => e
        raise "Error extracting project info from SARIF JSON file provided Exception: #{e}"
      end
    end

    def finding(result)
      finding = {}
      finding['status'] = 'failed'
      finding['code_desc'] = ''
      if get_location(result)['uri']
        finding['code_desc'] += " URL : #{get_location(result)['uri']}"
      end
      if get_location(result)['start_line']
        finding['code_desc'] += " LINE : #{get_location(result)['start_line']}"
      end
      if get_location(result)['start_column']
        finding['code_desc'] += " COLUMN : #{get_location(result)['start_column']}"
      end
      finding['code_desc'].strip!
      finding['run_time'] = NA_FLOAT
      finding['start_time'] = NA_STRING
      finding
    end

    def add_nist_tag_from_cwe(cweid, taxonomy_name, tags_node)
      entries = @cwe_nist_mapping.select { |x| cweid.include?(x[:cweid].to_s) && !x[:nistid].nil? }
      tags = entries.map { |x| x[:nistid] }
      result_tags = tags.empty? ? DEFAULT_NIST_TAG : tags.flatten.uniq
      if result_tags.count.positive?
        if !tags_node
          tags_node = {}
        end
        if !tags_node.key?(taxonomy_name)
          tags_node[taxonomy_name] = []
        end
        result_tags.each do |t|
          tags_node[taxonomy_name] |= [t]
        end
      end
      tags_node
    end

    def get_location(result)
      location_info = {}
      location_info['uri'] = result.dig('locations', 0, 'physicalLocation', 'artifactLocation', 'uri')
      location_info['start_line'] = result.dig('locations', 0, 'physicalLocation', 'region', 'startLine')
      location_info['start_column'] = result.dig('locations', 0, 'physicalLocation', 'region', 'startColumn')
      location_info
    end

    def get_rule_info(run, result, rule_id)
      finding = {}
      driver = run.dig('tool', 'driver')
      finding['driver_name'] = driver['name']
      finding['driver_version'] = driver['version']
      rules = driver['rules']
      if rules
        rule = rules.find { |x| x['id'].eql?(rule_id) }
        if rule
          finding['rule_name'] = rule&.[]('name')
          finding['rule_short_description'] = rule&.[]('shortDescription')&.[]('text')
          finding['rule_tags'] = get_tags(rule)
          finding['rule_name'] = rule&.[]('messageStrings')&.[]('default')&.[]('text') unless finding['rule_name']
        end
      end
      finding['rule_name'] = result&.[]('message')&.[]('text') unless finding['rule_name']
      finding
    end

    def get_tags(rule)
      result = {}
      Array(rule&.[]('relationships')).each do |relationship|
        taxonomy_name = relationship['target']['toolComponent']['name'].downcase
        taxonomy_id = relationship['target']['id']
        if !result.key?(taxonomy_name)
          result[taxonomy_name] = []
        end
        result[taxonomy_name] |= [taxonomy_id]
      end
      result
    end

    def parse_identifiers(rule_tags, ref)
      # Extracting id number from reference style CWE-297
      rule_tags[ref.downcase].map { |e| e.downcase.split("#{ref.downcase}-")[1] }
    rescue StandardError
      []
    end

    def impact(severity)
      severity_mapping = IMPACT_MAPPING[severity.to_sym]
      severity_mapping.nil? ? 0.1 : severity_mapping
    end

    def parse_mapper
      csv_data = CSV.read(CWE_NIST_MAPPING_FILE, **{ encoding: 'UTF-8',
                                                   headers: true,
                                                   header_converters: :symbol,
                                                   converters: :all })
      csv_data.map(&:to_hash)
    end

    def desc_tags(data, label)
      { data: data || NA_STRING, label: label || NA_STRING }
    end

    def process_item(run, result, controls)
      printf("\rProcessing: %s", $spinner.next)
      control = controls.find { |x| x['id'].eql?(result['ruleId']) }

      if control
        control['results'] << finding(result)
      else
        rule_info = get_rule_info(run, result, result['ruleId'])
        item = {}
        item['tags']               = rule_info['rule_tags']
        item['descriptions']       = []
        item['refs']               = NA_ARRAY
        item['source_location']    = { ref: get_location(result)['uri'], line: get_location(result)['start_line'] }
        item['descriptions']       = NA_ARRAY
        item['title']              = rule_info['rule_name'].to_s
        item['id']                 = result['ruleId'].to_s
        item['desc']               = rule_info['rule_short_description'].to_s
        item['impact']             = impact(result['level'].to_s)
        item['code']               = NA_STRING
        item['results']            = [finding(result)]
        item['tags']               = add_nist_tag_from_cwe(parse_identifiers(rule_info['rule_tags'], 'CWE'), 'nist', item['tags'])
        controls << item
      end
    end

    def to_hdf
      controls = []
      @sarif_log['runs'].each do |run|
        run['results'].each do |result|
          process_item(run, result, controls)
        end
      end

      scaninfo = extract_scaninfo(@sarif_log)
      results = HeimdallDataFormat.new(profile_name: scaninfo['policy'],
                                       version: scaninfo['version'],
                                       title: scaninfo['projectName'],
                                       summary: scaninfo['summary'],
                                       controls: controls,
                                       target_id: scaninfo['projectName'])
      results.to_hdf
    end
  end
end
