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

const IV = 16

// encrypt
const enc = t=>{
  const iv = crypto.randomBytes(IV)
  const c = crypto.createCipheriv('aes-256-cbc',KEY,iv)
  return iv.toString('hex')+':'+c.update(t,'utf8','hex')+c.final('hex')
}

// decrypt
const dec = e=>{
  const [ivHex,data]=e.split(':')
  const iv=Buffer.from(ivHex,'hex')
  const d=crypto.createDecipheriv('aes-256-cbc',KEY,iv)
  return d.update(data,'hex','utf8')+d.final('utf8')
}

// pack
const pack = s=>enc(Buffer.from(s).toString('base64'))

const sign = t=>crypto.createHmac('sha256',KEY).update(t).digest('hex')

const limiter = rateLimit({windowMs:10000,max:25})

// upload script
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

// token endpoint
app.get('/token/:id',(req,res)=>{
  const id=req.params.id
  const ts=Date.now()
  const t = id + "." + crypto.randomBytes(6).toString('hex')
  const sig=sign(t+ts)

  res.setHeader('Content-Type','text/plain')
  res.setHeader('X-Content-Type-Options','nosniff')

  // 1 line loader, URL match route /load
  res.send(`return(function()local t="${t}"local ts="${ts}"local sig="${sig}"return game:HttpGet("https://${req.get('host')}/load?t="..t.."&ts="..ts.."&sig="..sig)end)()`)
})

// load endpoint
app.get('/load',limiter,(req,res)=>{
  try{
    const {t,ts,sig}=req.query
    if(!t||!ts||!sig) return res.status(400).send('bad')

    // verify sig
    if(sig!==sign(t+ts)) return res.status(403).send('invalid sig')

    // check time (60s)
    if(Date.now()-parseInt(ts)>60000) return res.status(403).send('expired')

    // get id from token
    const id = t.split('.')[0]
    const f=path.join(DIR,id+'.enc')
    if(!fs.existsSync(f)) return res.status(404).send('not found')

    const payload=fs.readFileSync(f,'utf8')
    const raw = dec(payload)
    const src = Buffer.from(raw,'base64').toString()

    res.setHeader('Content-Type','text/plain')
    res.setHeader('X-Content-Type-Options','nosniff')
    res.setHeader('Cache-Control','no-store')

    res.send(src)
  }catch{
    res.status(500).send('err')
  }
})

app.listen(PORT,()=>console.log("running "+PORT))
