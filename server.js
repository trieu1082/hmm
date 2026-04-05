const express = require('express')
const crypto = require('crypto')
const fs = require('fs-extra')
const path = require('path')
const rateLimit = require('express-rate-limit')
require('dotenv').config()

const app = express()
const PORT = process.env.PORT || 3000

const KEY = Buffer.from(
  process.env.SECRET_KEY || crypto.randomBytes(32).toString('hex'),
  'hex'
)

app.use(express.json({limit:"2mb"}))
app.use(express.urlencoded({extended:true}))
app.use(express.static(path.join(__dirname,'public')))

const DIR = path.join(__dirname,'scripts')
fs.ensureDirSync(DIR)

const TOKENS = new Map()
const IV = 16

const enc = t=>{
  const iv = crypto.randomBytes(IV)
  const c = crypto.createCipheriv('aes-256-cbc',KEY,iv)
  return iv.toString('hex')+':'+c.update(t,'utf8','hex')+c.final('hex')
}

const pack = s=>{
  return enc(Buffer.from(s).toString('base64'))
}

const sign = t=>crypto.createHmac('sha256',KEY).update(t).digest('hex')

const badUA = ua=>{
  ua=(ua||'').toLowerCase()
  return ['curl','wget','python','postman','insomnia','httpclient','axios'].some(v=>ua.includes(v))
}

const limiter = rateLimit({windowMs:10000,max:25})

app.post('/upload',limiter,(req,res)=>{
  try{
    const c=req.body.content
    if(!c) return res.status(400).json({error:'no content'})

    const id=crypto.randomBytes(8).toString('hex')
    fs.writeFileSync(path.join(DIR,id+'.enc'),pack(c))

    const base=`https://${req.get('host')}`

    res.json({
      id,
      loader:`loadstring(game:HttpGet("${base}/token/${id}"))()`
    })
  }catch{
    res.status(500).json({error:'server'})
  }
})

app.get('/token/:id',(req,res)=>{
  if(badUA(req.headers['user-agent'])) return res.status(403).send('blocked')

  const id=req.params.id
  const t=crypto.randomBytes(12).toString('hex')
  const ts=Date.now()

  TOKENS.set(t,{id,time:ts})

  const sig=sign(t+ts)

  res.send(`
return (function()
  local t="${t}"
  local ts="${ts}"
  local sig="${sig}"
  return game:HttpGet("https://${req.get('host')}/load/${id}?t="..t.."&ts="..ts.."&sig="..sig)
end)()
`)
})

app.get('/load/:id',limiter,(req,res)=>{
  try{
    const {t,ts,sig}=req.query
    const d=TOKENS.get(t)

    if(!d) return res.status(403).send('bad token')
    if(Date.now()-d.time>10000){TOKENS.delete(t);return res.status(403).send('expired')}
    if(sig!==sign(t+ts)) return res.status(403).send('invalid sig')

    TOKENS.delete(t)

    const f=path.join(DIR,req.params.id+'.enc')
    if(!fs.existsSync(f)) return res.status(404).send('not found')

    const payload=fs.readFileSync(f,'utf8')

    res.setHeader('Content-Type','text/plain')

    res.send(`
local d="${payload}"
local Http=game:GetService("HttpService")

local function b64(x)return Http:Base64Decode(x)end
local function dec(e)local _,dat=e:match("([^:]+):(.+)")return dat end

local ok,src=pcall(function()
  return b64(dec(d))
end)

if not ok then return end

return loadstring(src)()
`)
  }catch{
    res.status(500).send('err')
  }
})

app.listen(PORT,()=>console.log("running "+PORT))
