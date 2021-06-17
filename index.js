const fs          = require('fs');
const net         = require('net');
const url         = require('url');
const axios       = require('axios');
const agent       = require('user-agents');
const agents      = require('useragent');
const cheerio     = require('cheerio');
const { lookup }  = require('node-whois');
const { program } = require('commander');
const ProxyAgent  = require('https-proxy-agent');

/**
 * Command arguments. */
program.option('-d, --domain <domain>', 'Domain to use');
program.option('-p, --proxy <address>', 'Proxy server to use');
program.parse(process.argv);
const args  = program.opts();
const file  = fs.readFileSync(__dirname + '/domains.txt', 'utf-8');
let domains = file.split('\n').filter(l => l.length > 0 && l.charAt(0) !== '!');

/**
* Find a suitable user agent */
const useragents = new agent(data => {
  const props = agents.parse(data.userAgent);
  const { family, major } = props.os;
  return family === 'Android' && major > 6
});

/**
 * Sleep function */
const sleep = (msec) => new Promise(res => setTimeout(res, msec));
const whois = (domain) => new Promise((res, rej) => lookup(domain, (err, data) => {
  if (err) return rej(err);
  res(data);
}))

/**
 * Scrape helper */
const gatherProxies = async () => {
  if (args.proxy) {
    return [args.proxy];
  }

  try
  {
    /**
     * Send request and dissect response */
    const useragent = (new agent()).toString();
    const { data } = await axios.get("http://sslproxies.org/", { headers: { 'User-Agent': useragent } })
    const $ = cheerio.load(data);

    const proxies = [];
    $('tbody tr').each((i, v) => {
      const [ ip, port, code ] = $(v).children('td').map((i, c) => {
        return $(c).text();
      });

      if (net.isIP(ip))
      {
        proxies.push(`${ip}:${port}`);
      }
    });

    return proxies;
  }
  catch (err)
  {
  }
};

/**
 * Scanning helper */
const scan = async (proxies) => {
  let found = [];

  /**
   * const randomDomain = Math.floor(Math.random() * (domains.length - 1));
   * const domain       = args.domain || domains[randomDomain];
   * const { hostname } = url.parse(domain);
   */
  for (let idxDomain = 0; idxDomain < domains.length; ++idxDomain)
  {
    /**
     * Get domain and hostname */
    const domain       = domains[idxDomain];
    const { hostname } = url.parse(domain);

    /**
     * We'll try scraping the site
     * 10 times to find new domains. */
    console.log(`Scraping: ${hostname}`);
    for (let i = 0; i < 10; ++i)
    {
      try
      {
        /**
         * Setup proxy and user-agent */
        const random    = Math.floor(Math.random() * (proxies.length - 1));
        const proxy     = proxies[random];
        const useragent = useragents().toString();

        /**
         * Send request and dissect response */
        const { data } = await axios.get(domain, {
          agent: new ProxyAgent(`http://${proxy}`),
          headers: { 'User-Agent': useragent },
          maxRedirects: 0
        });

        const $    = cheerio.load(data);
        const btn  = $('a.btn');
        const link = btn.attr('href');
        const [ uri ] = link.split('?');

        /**
         * Check if it's a newly found domain */
        if (domains.indexOf(uri) === -1)
        {
          found.push(uri);
          console.log(`Found new URL: ${uri}`);
        }
      }
      catch (err)
      {
        let error;
        const { status = 0, headers } = err.response || {};
        switch (status)
        {
	  /**
           * They added a new method by redirecting with a 302 status */
          case 302: {
            const [ uri ] = headers.location.split('?');
            found.push(headers.location);
            console.log(`Found new URL: ${uri}`);
            break;
          }

          case 404:
            error = `Scraping: URL removed - ${hostname} (${status})`;
            break;

          default:
            error = `Scraping: Error encountered - ${hostname} (${status})`;
            break;
        }

        if (error) {
          /**
           * In case that we encountered an error
           * we'll break out of the loop */
          console.error(error);
          break;
        }
      }
   
      /**
       * Sleep for some time */
      await sleep(2000);
    }
  }

  /**
   * Remove duplicates from found
   * and add to domain list.  */
  found   = [...new Set(found)];
  domains = [...domains, ...found];
  console.log('Current domains:');
  domains.forEach(d => console.log(d));
};

/**
 * Gather procies and start scanning */
gatherProxies().then((proxies) => scan(proxies));

